param(
    [string]$RepoRoot = "C:\src\incursa\quic-dotnet",
    [string]$RequirementsRoot = "C:\src\incursa\quic-dotnet\specs\requirements\quic",
    [string]$TriagePath = "C:\src\incursa\quic-dotnet\specs\generated\quic\quic-requirement-coverage-triage.json",
    [string]$TriageScriptPath = "C:\src\incursa\quic-dotnet\scripts\spec-trace\Generate-QuicRequirementCoverageTriage.ps1",

    [string]$OutputDirectory = "C:\src\incursa\quic-dotnet\specs\codex_work\loop",
    [string]$CodexCommand = "codex",
    [string]$Sandbox = "workspace-write",
    [string]$Model = "gpt-5.4-mini",
    [string]$ReasoningEffort = "high",

    [string[]]$RfcOrder = @(),
    [string[]]$SectionPrefixAllowList = @(),
    [int]$BatchTargetCount = 4,
    [int]$BatchMaxCount = 8,
    [int]$MaxIterations = 25,
    [int]$NoProgressLimit = 2,
    [int]$CooldownSeconds = 2
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-ExistingPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Path does not exist: $Path"
    }

    return (Resolve-Path -LiteralPath $Path).Path
}

function Ensure-Directory {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }

    return (Resolve-Path -LiteralPath $Path).Path
}

function Get-ExceptionDetail {
    param([Parameter(Mandatory = $true)][System.Exception]$Exception)

    $messages = New-Object System.Collections.Generic.List[string]
    $current = $Exception

    while ($null -ne $current) {
        if (-not [string]::IsNullOrWhiteSpace($current.Message)) {
            $messages.Add($current.Message.Trim())
        }

        $current = $current.InnerException
    }

    if ($messages.Count -eq 0) {
        return $Exception.ToString()
    }

    return ($messages -join " | Inner: ")
}

function Test-IsWindows {
    return $env:OS -eq "Windows_NT"
}

function Resolve-CodexCommand {
    param([Parameter(Mandatory = $true)][string]$Command)

    if (-not (Test-IsWindows) -or $Command -ne "codex") {
        return $Command
    }

    foreach ($candidate in @("codex.cmd", "codex.exe")) {
        $resolved = Get-Command -Name $candidate -ErrorAction SilentlyContinue
        if ($resolved -and $resolved.CommandType -eq "Application" -and -not [string]::IsNullOrWhiteSpace($resolved.Path)) {
            return $resolved.Path
        }
    }

    throw "Unable to resolve a runnable Codex executable. Looked for codex.cmd and codex.exe on PATH."
}

function Write-CodexStreamLine {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("stdout", "stderr", "heartbeat")]
        [string]$StreamName,

        [AllowEmptyString()]
        [Parameter(Mandatory = $true)]
        [string]$Line,

        [Parameter(Mandatory = $true)]
        [string]$LogPath
    )

    if ([string]::IsNullOrWhiteSpace($Line)) {
        return
    }

    $logDirectory = Split-Path -Path $LogPath -Parent
    if (-not [string]::IsNullOrWhiteSpace($logDirectory)) {
        Ensure-Directory -Path $logDirectory | Out-Null
    }

    [System.IO.File]::AppendAllText($LogPath, "[$StreamName] $Line$([Environment]::NewLine)")

    $summary = ($Line -replace '\s+', ' ').Trim()
    if ($summary.Length -gt 220) {
        $summary = $summary.Substring(0, 217) + "..."
    }

    $color = switch ($StreamName) {
        "stdout"    { "Cyan" }
        "stderr"    { "DarkYellow" }
        "heartbeat" { "DarkGray" }
    }

    Write-Host "  $summary" -ForegroundColor $color
}

function Get-StateCount {
    param(
        [Parameter(Mandatory = $true)]$StateObject,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($null -eq $StateObject) {
        return 0
    }

    if ($StateObject.PSObject.Properties.Name -contains $Name) {
        return [int]$StateObject.$Name
    }

    return 0
}

function Get-TriageSnapshot {
    param([Parameter(Mandatory = $true)][string]$Path)

    $json = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -Depth 100
    $byState = $json.summary.by_state

    $traceClean = Get-StateCount -StateObject $byState -Name "trace_clean"
    $missingCoverageContract = Get-StateCount -StateObject $byState -Name "missing_coverage_contract"
    $missingXrefs = Get-StateCount -StateObject $byState -Name "covered_but_missing_xrefs"
    $proofTooBroad = Get-StateCount -StateObject $byState -Name "covered_but_proof_too_broad"
    $partial = Get-StateCount -StateObject $byState -Name "partially_covered"
    $uncoveredUnblocked = Get-StateCount -StateObject $byState -Name "uncovered_unblocked"
    $uncoveredBlocked = Get-StateCount -StateObject $byState -Name "uncovered_blocked"

    $fingerprint = "$traceClean|$missingCoverageContract|$missingXrefs|$proofTooBroad|$partial|$uncoveredUnblocked|$uncoveredBlocked"

    return [pscustomobject]@{
        TraceClean              = $traceClean
        MissingCoverageContract = $missingCoverageContract
        MissingXrefs            = $missingXrefs
        ProofTooBroad           = $proofTooBroad
        Partial                 = $partial
        UncoveredUnblocked      = $uncoveredUnblocked
        UncoveredBlocked        = $uncoveredBlocked
        Fingerprint             = $fingerprint
    }
}

function Format-TriageSnapshot {
    param([Parameter(Mandatory = $true)]$Snapshot)

    return "trace_clean=$($Snapshot.TraceClean), missing_coverage_contract=$($Snapshot.MissingCoverageContract), missing_xrefs=$($Snapshot.MissingXrefs), proof_too_broad=$($Snapshot.ProofTooBroad), partially_covered=$($Snapshot.Partial), uncovered_unblocked=$($Snapshot.UncoveredUnblocked), uncovered_blocked=$($Snapshot.UncoveredBlocked)"
}

function Get-LoopPlan {
    param([AllowNull()][string[]]$RfcOrder = @())

    $defaultRfcOrder = @(
        "RFC9002",
        "RFC9000 bounded clusters",
        "RFC9001"
    )

    if ($null -eq $RfcOrder -or $RfcOrder.Count -eq 0) {
        $resolvedRfcOrder = @($defaultRfcOrder)
    }
    else {
        $resolvedRfcOrder = @($RfcOrder | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($resolvedRfcOrder.Count -eq 0) {
            $resolvedRfcOrder = @($defaultRfcOrder)
        }
    }

    $orderText = $resolvedRfcOrder -join " -> "
    $lockedFamiliesNote = if ($resolvedRfcOrder.Count -gt 1) {
        "This runner stays in uncovered_unblocked only and walks $orderText; blocked families stay out of the default order."
    }
    else {
        "This runner stays in uncovered_unblocked only and focuses on $orderText; blocked families stay out of the default order."
    }

    return [pscustomobject]@{
        RfcOrder = $resolvedRfcOrder
        TierOrder = @(
            "uncovered_unblocked"
        )
        TierDescriptions = @{
            uncovered_unblocked = "implementation-backed uncovered requirements"
        }
        LockedFamiliesNote = $lockedFamiliesNote
    }
}

function Convert-TierToTriageState {
    param([Parameter(Mandatory = $true)][string]$Tier)

    switch ($Tier) {
        "metadata_only"       { return "covered_but_missing_xrefs" }
        "partials"            { return "partially_covered" }
        "proof_narrowing"     { return "covered_but_proof_too_broad" }
        "uncovered_unblocked" { return "uncovered_unblocked" }
        default               { return "" }
    }
}

function Convert-RfcFocusToRequirementRfc {
    param([Parameter(Mandatory = $true)][string]$CurrentRfc)

    if ([string]::IsNullOrWhiteSpace($CurrentRfc)) {
        return ""
    }

    if ($CurrentRfc -match "RFC8999") {
        return "RFC8999"
    }

    if ($CurrentRfc -match "RFC9000") {
        return "RFC9000"
    }

    if ($CurrentRfc -match "RFC9001") {
        return "RFC9001"
    }

    if ($CurrentRfc -match "RFC9002") {
        return "RFC9002"
    }

    return ""
}

function Get-RequirementBatchCandidates {
    param(
        [Parameter(Mandatory = $true)][string]$TriagePath,
        [Parameter(Mandatory = $true)][string]$CurrentRfcFocus,
        [Parameter(Mandatory = $true)][string]$CurrentTier,
        [Parameter(Mandatory = $true)][int]$TargetCount,
        [Parameter(Mandatory = $true)][int]$MaxCount,
        [AllowNull()][string[]]$SectionPrefixAllowList = @(),
        [AllowNull()][string[]]$ExcludedBatchKeys = @()
    )

    $triageState = Convert-TierToTriageState -Tier $CurrentTier
    if ([string]::IsNullOrWhiteSpace($triageState)) {
        return [pscustomobject]@{
            TriagedState   = ""
            RequirementRfc = ""
            SectionPrefix  = ""
            TargetCount    = $TargetCount
            MaxCount       = $MaxCount
            Requirements   = @()
        }
    }

    if ($null -eq $ExcludedBatchKeys) {
        $ExcludedBatchKeys = @()
    }

    if ($null -eq $SectionPrefixAllowList) {
        $SectionPrefixAllowList = @()
    }

    $requirementRfc = Convert-RfcFocusToRequirementRfc -CurrentRfc $CurrentRfcFocus
    $json = Get-Content -LiteralPath $TriagePath -Raw | ConvertFrom-Json -Depth 100
    $requirements = @($json.requirements)
    $groupOrder = New-Object System.Collections.Generic.List[string]
    $groupIndex = @{}

    for ($i = 0; $i -lt $requirements.Count; $i++) {
        $requirement = $requirements[$i]

        if ($requirement.state -ne $triageState) {
            continue
        }

        if (-not [string]::IsNullOrWhiteSpace($requirementRfc) -and $requirement.rfc -ne $requirementRfc) {
            continue
        }

        if (-not (Test-IsSectionPrefixAllowed -RequirementSectionPrefix $requirement.section_prefix -AllowedSectionPrefixes $SectionPrefixAllowList)) {
            continue
        }

        $sectionPrefix = if ([string]::IsNullOrWhiteSpace($requirement.section_prefix)) { "__none__" } else { $requirement.section_prefix }
        $batchKey = Get-RequirementBatchKey -TriagedState $triageState -RequirementRfc $requirement.rfc -SectionPrefix $requirement.section_prefix

        if ($ExcludedBatchKeys -contains $batchKey) {
            continue
        }

        if (-not $groupIndex.ContainsKey($sectionPrefix)) {
            $groupIndex[$sectionPrefix] = [pscustomobject]@{
                SectionPrefix = if ($sectionPrefix -eq "__none__") { "" } else { $sectionPrefix }
                FirstIndex    = $i
                Requirements  = New-Object System.Collections.Generic.List[object]
            }

            [void]$groupOrder.Add($sectionPrefix)
        }

        $groupIndex[$sectionPrefix].Requirements.Add([pscustomobject]@{
            RequirementId = $requirement.requirement_id
            Title         = $requirement.title
            Rfc           = $requirement.rfc
            State         = $requirement.state
            SectionPrefix = $requirement.section_prefix
            Index         = $i
        })
    }

    if ($groupOrder.Count -eq 0) {
        return [pscustomobject]@{
            TriagedState   = $triageState
            RequirementRfc = $requirementRfc
            SectionPrefix  = ""
            BatchKey       = ""
            TargetCount    = $TargetCount
            MaxCount       = $MaxCount
            Requirements   = @()
        }
    }

    $bestSectionPrefix = $null
    $bestCount = -1
    $bestFirstIndex = [int]::MaxValue

    foreach ($sectionPrefix in $groupOrder) {
        $group = $groupIndex[$sectionPrefix]
        $count = $group.Requirements.Count

        if ($count -gt $bestCount -or ($count -eq $bestCount -and $group.FirstIndex -lt $bestFirstIndex)) {
            $bestSectionPrefix = $sectionPrefix
            $bestCount = $count
            $bestFirstIndex = $group.FirstIndex
        }
    }

    $selected = @($groupIndex[$bestSectionPrefix].Requirements | Select-Object -First $MaxCount)

    return [pscustomobject]@{
        TriagedState   = $triageState
        RequirementRfc = $requirementRfc
        SectionPrefix  = $groupIndex[$bestSectionPrefix].SectionPrefix
        BatchKey       = Get-RequirementBatchKey -TriagedState $triageState -RequirementRfc $requirementRfc -SectionPrefix $groupIndex[$bestSectionPrefix].SectionPrefix
        TargetCount    = $TargetCount
        MaxCount       = $MaxCount
        Requirements   = $selected
    }
}

function Format-RequirementBatchCandidates {
    param([Parameter(Mandatory = $true)]$BatchCandidates)

    if ($null -eq $BatchCandidates -or $BatchCandidates.Requirements.Count -eq 0) {
        return "none"
    }

    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($requirement in $BatchCandidates.Requirements) {
        $sectionText = if ([string]::IsNullOrWhiteSpace($requirement.SectionPrefix)) { "n/a" } else { $requirement.SectionPrefix }
        [void]$lines.Add(("- {0} [{1} / {2}] {3}" -f $requirement.RequirementId, $requirement.Rfc, $sectionText, $requirement.Title))
    }

    return ($lines -join [Environment]::NewLine)
}

function Get-RequirementBatchKey {
    param(
        [Parameter(Mandatory = $true)][string]$TriagedState,
        [Parameter(Mandatory = $true)][string]$RequirementRfc,
        [Parameter(Mandatory = $true)][string]$SectionPrefix
    )

    $stateText = if ([string]::IsNullOrWhiteSpace($TriagedState)) { "n/a" } else { $TriagedState.Trim() }
    $rfcText = if ([string]::IsNullOrWhiteSpace($RequirementRfc)) { "n/a" } else { $RequirementRfc.Trim() }
    $sectionText = if ([string]::IsNullOrWhiteSpace($SectionPrefix)) { "n/a" } else { $SectionPrefix.Trim() }
    return "$stateText|$rfcText|$sectionText"
}

function Test-IsSectionPrefixAllowed {
    param(
        [AllowEmptyString()][string]$RequirementSectionPrefix,
        [AllowNull()][string[]]$AllowedSectionPrefixes = @()
    )

    if ($null -eq $AllowedSectionPrefixes -or $AllowedSectionPrefixes.Count -eq 0) {
        return $true
    }

    $normalizedRequirementPrefix = if ([string]::IsNullOrWhiteSpace($RequirementSectionPrefix)) { "" } else { $RequirementSectionPrefix.Trim() }

    foreach ($allowedPrefix in $AllowedSectionPrefixes) {
        if ([string]::IsNullOrWhiteSpace($allowedPrefix)) {
            continue
        }

        if ($normalizedRequirementPrefix -eq $allowedPrefix.Trim()) {
            return $true
        }
    }

    return $false
}

function Read-LineList {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return @()
    }

    $lines = Get-Content -LiteralPath $Path | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    if ($null -eq $lines) {
        return @()
    }

    return @($lines | Select-Object -Unique)
}

function Write-LineList {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [AllowNull()][string[]]$Lines
    )

    $directory = Split-Path -Path $Path -Parent
    if (-not [string]::IsNullOrWhiteSpace($directory) -and -not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }

    if ($null -eq $Lines) {
        $Lines = @()
    }

    if (@($Lines).Count -eq 0) {
        if (Test-Path -LiteralPath $Path) {
            Remove-Item -LiteralPath $Path -Force
        }
        return
    }

    Set-Content -LiteralPath $Path -Value $Lines -Encoding utf8
}

function Add-LineIfMissing {
    param(
        [AllowNull()][string[]]$Lines,
        [Parameter(Mandatory = $true)][string]$Line
    )

    if ($null -eq $Lines) {
        $Lines = @()
    }

    if ($Lines -contains $Line) {
        return @($Lines)
    }

    return @($Lines) + @($Line)
}

function Test-IsDeadEndStopReason {
    param([AllowEmptyString()][string]$StopReason)

    if ([string]::IsNullOrWhiteSpace($StopReason)) {
        return $false
    }

    return $StopReason -match '(?i)no implementation-backed (?:proof seam|slice|batch)|no focused proof seam|dead end|beyond wire/transport-parameter codecs|repo does not expose|does not expose|cid issuance|lifecycle state|focused proof'
}

function Test-HasRemainingEligibleUncoveredBatch {
    param(
        [Parameter(Mandatory = $true)][string]$TriagePath,
        [AllowNull()][string[]]$SectionPrefixAllowList = @(),
        [AllowNull()][string[]]$ExcludedBatchKeys = @()
    )

    if ($null -eq $SectionPrefixAllowList) {
        $SectionPrefixAllowList = @()
    }

    if ($null -eq $ExcludedBatchKeys) {
        $ExcludedBatchKeys = @()
    }

    $json = Get-Content -LiteralPath $TriagePath -Raw | ConvertFrom-Json -Depth 100
    foreach ($requirement in @($json.requirements)) {
        if ($requirement.state -ne "uncovered_unblocked") {
            continue
        }

        if (-not (Test-IsSectionPrefixAllowed -RequirementSectionPrefix $requirement.section_prefix -AllowedSectionPrefixes $SectionPrefixAllowList)) {
            continue
        }

        $batchKey = Get-RequirementBatchKey -TriagedState $requirement.state -RequirementRfc $requirement.rfc -SectionPrefix $requirement.section_prefix
        if ($ExcludedBatchKeys -contains $batchKey) {
            continue
        }

        return $true
    }

    return $false
}

function Get-IterationOutcomeKind {
    param(
        [Parameter(Mandatory = $true)][string]$Status,
        [Parameter(Mandatory = $true)][string]$BatchDisposition,
        [Parameter(Mandatory = $true)][bool]$StopNow,
        [AllowEmptyString()][string]$SelectionOutcome = "",
        [Parameter(Mandatory = $true)][bool]$TriageChanged,
        [Parameter(Mandatory = $true)][bool]$Progressed
    )

    switch ($Status) {
        "Exception" { return "Exception" }
        "Failed"    { return "Failed" }
    }

    switch ($BatchDisposition) {
        "DeadEndSkipped"   { return "DeadEndSkipped" }
        "NoProgressSkipped" { return "NoProgressSkipped" }
        "NoCandidates"     { return "NoCandidates" }
    }

    if ($StopNow -and -not [string]::IsNullOrWhiteSpace($SelectionOutcome) -and $SelectionOutcome -eq "RepoExhausted") {
        return "RepoExhausted"
    }

    if ($TriageChanged -or $Progressed) {
        return "Worked"
    }

    return "NoChange"
}

function New-LoopState {
    return [pscustomobject]@{
        RfcIndex  = 0
        TierIndex = 0
    }
}

function Get-LoopStateDetails {
    param(
        [Parameter(Mandatory = $true)]$LoopPlan,
        [Parameter(Mandatory = $true)]$LoopState
    )

    $currentRfc = $null
    if ($LoopState.RfcIndex -lt $LoopPlan.RfcOrder.Count) {
        $currentRfc = $LoopPlan.RfcOrder[$LoopState.RfcIndex]
    }

    $currentTier = $null
    if ($LoopState.TierIndex -lt $LoopPlan.TierOrder.Count) {
        $currentTier = $LoopPlan.TierOrder[$LoopState.TierIndex]
    }

    $nextTier = "n/a"
    if ($null -ne $currentRfc) {
        if ($LoopState.TierIndex -lt ($LoopPlan.TierOrder.Count - 1)) {
            $nextTier = $LoopPlan.TierOrder[$LoopState.TierIndex + 1]
        }
        elseif ($LoopState.RfcIndex -lt ($LoopPlan.RfcOrder.Count - 1)) {
            $nextTier = "next_rfc"
        }
    }

    $tierDescription = "n/a"
    if ($null -ne $currentTier -and $LoopPlan.TierDescriptions.ContainsKey($currentTier)) {
        $tierDescription = $LoopPlan.TierDescriptions[$currentTier]
    }

    return [pscustomobject]@{
        RfcIndex               = $LoopState.RfcIndex
        TierIndex              = $LoopState.TierIndex
        CurrentRfc             = if ($null -ne $currentRfc) { $currentRfc } else { "n/a" }
        CurrentTier            = if ($null -ne $currentTier) { $currentTier } else { "n/a" }
        CurrentTierDescription  = $tierDescription
        NextTier               = $nextTier
        SecondaryRfcChecked    = $LoopState.RfcIndex -ge 1
        IsFinalRfc             = $LoopState.RfcIndex -ge ($LoopPlan.RfcOrder.Count - 1)
        IsFinalTier            = $LoopState.TierIndex -ge ($LoopPlan.TierOrder.Count - 1)
    }
}

function Get-LoopControlSectionText {
    param([AllowEmptyString()][string]$ResultText)

    if ([string]::IsNullOrWhiteSpace($ResultText)) {
        return ""
    }

    $sectionMatch = [regex]::Match($ResultText, '(?ims)^##\s*Loop Control\s*(.*?)(?=^##\s|\z)')
    if ($sectionMatch.Success) {
        return $sectionMatch.Groups[1].Value
    }

    return $ResultText
}

function Get-DirectiveFieldValue {
    param(
        [AllowEmptyString()][string]$Text,
        [Parameter(Mandatory = $true)][string]$FieldName
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ""
    }

    $match = [regex]::Match($Text, "(?im)^\s*$([regex]::Escape($FieldName))\s*:\s*(.+?)\s*$")
    if ($match.Success) {
        return $match.Groups[1].Value.Trim()
    }

    return ""
}

function Normalize-NotApplicableValue {
    param([AllowEmptyString()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return ""
    }

    if ($Value.Trim().ToLowerInvariant() -eq "n/a") {
        return ""
    }

    return $Value.Trim()
}

function Resolve-LoopTransition {
    param(
        [Parameter(Mandatory = $true)]$LoopPlan,
        [Parameter(Mandatory = $true)]$LoopState,
        [Parameter(Mandatory = $true)]$Directive,
        [Parameter(Mandatory = $true)][bool]$HasCurrentBatchCandidates
    )

    $stateDetails = Get-LoopStateDetails -LoopPlan $LoopPlan -LoopState $LoopState
    $nextState = [pscustomobject]@{
        RfcIndex  = $LoopState.RfcIndex
        TierIndex = $LoopState.TierIndex
    }

    $directiveStatus = if ([string]::IsNullOrWhiteSpace($Directive.LoopStatus)) { "Continue" } else { $Directive.LoopStatus.Trim() }
    $directiveOutcome = if ([string]::IsNullOrWhiteSpace($Directive.SelectionOutcome)) { "" } else { $Directive.SelectionOutcome.Trim() }
    $directiveNextTier = Normalize-NotApplicableValue -Value $Directive.NextTier
    $directiveStopReason = Normalize-NotApplicableValue -Value $Directive.StopReason

    $effectiveStatus = "Continue"
    $effectiveOutcome = if ($directiveOutcome) { $directiveOutcome } else { "" }
    $effectiveNextTier = "n/a"
    $shouldStop = $false
    $stopReason = ""
    $progressed = $false

    switch ($directiveOutcome) {
        "Worked" {
            $effectiveNextTier = "n/a"
            $progressed = $true
        }

        "NoSliceInCurrentTier" {
            $progressed = $true

            if ($HasCurrentBatchCandidates) {
                $effectiveOutcome = "Worked"
                $effectiveStatus = "Continue"
                $effectiveNextTier = $LoopPlan.TierOrder[$LoopState.TierIndex]
            }
            elseif ($stateDetails.IsFinalTier) {
                if ($stateDetails.IsFinalRfc) {
                    $effectiveOutcome = "RepoExhausted"
                    $effectiveStatus = "Stop"
                    $shouldStop = $true
                    $stopReason = if ([string]::IsNullOrWhiteSpace($directiveStopReason)) {
                        "Repo exhausted: the current RFC focus and the secondary RFC focus are both exhausted."
                    }
                    else {
                        $directiveStopReason
                    }
                }
                else {
                    $effectiveOutcome = "NoSliceInCurrentRFC"
                    $nextState.RfcIndex = $LoopState.RfcIndex + 1
                    $nextState.TierIndex = 0
                    $effectiveNextTier = "next_rfc"
                }
            }
            else {
                $nextState.TierIndex = $LoopState.TierIndex + 1
                $effectiveNextTier = $LoopPlan.TierOrder[$nextState.TierIndex]
            }
        }

        "NoSliceInCurrentRFC" {
            $progressed = $true

            if ($HasCurrentBatchCandidates) {
                $effectiveOutcome = "Worked"
                $effectiveStatus = "Continue"
                $effectiveNextTier = $LoopPlan.TierOrder[$LoopState.TierIndex]
            }
            elseif ($stateDetails.IsFinalRfc) {
                $effectiveOutcome = "RepoExhausted"
                $effectiveStatus = "Stop"
                $shouldStop = $true
                $stopReason = if ([string]::IsNullOrWhiteSpace($directiveStopReason)) {
                    "Repo exhausted: no secondary RFC focus remains."
                }
                else {
                    $directiveStopReason
                }
            }
            else {
                $nextState.RfcIndex = $LoopState.RfcIndex + 1
                $nextState.TierIndex = 0
                $effectiveNextTier = "next_rfc"
            }
        }

        "RepoExhausted" {
            $progressed = $true
            $effectiveStatus = "Stop"
            $shouldStop = $true
            $stopReason = if ([string]::IsNullOrWhiteSpace($directiveStopReason)) {
                if ($stateDetails.IsFinalRfc) {
                    "Repo exhausted: the current RFC focus and the secondary RFC focus are both exhausted."
                }
                else {
                    "Repo exhausted."
                }
            }
            else {
                $directiveStopReason
            }
        }

        default {
            if ($directiveStatus -eq "Stop" -and $stateDetails.IsFinalRfc -and $stateDetails.IsFinalTier) {
                $progressed = $true
                $effectiveStatus = "Stop"
                $effectiveOutcome = "RepoExhausted"
                $shouldStop = $true
                $stopReason = if ([string]::IsNullOrWhiteSpace($directiveStopReason)) {
                    "Repo exhausted by the current loop state."
                }
                else {
                    $directiveStopReason
                }
            }
        }
    }

    if (-not $shouldStop -and $directiveStatus -eq "Stop") {
        $effectiveStatus = "Continue"
    }

    $nextStateDetails = Get-LoopStateDetails -LoopPlan $LoopPlan -LoopState $nextState

    return [pscustomobject]@{
        DirectiveLoopStatus      = $directiveStatus
        DirectiveSelectionOutcome = $directiveOutcome
        DirectiveNextTier        = if ([string]::IsNullOrWhiteSpace($Directive.NextTier)) { "" } else { $Directive.NextTier.Trim() }
        DirectiveStopReason      = $directiveStopReason
        EffectiveLoopStatus      = $effectiveStatus
        EffectiveSelectionOutcome = $effectiveOutcome
        EffectiveNextTier        = $effectiveNextTier
        NextState                = $nextState
        NextStateDetails         = $nextStateDetails
        ShouldStop               = $shouldStop
        StopReason               = $stopReason
        Progressed               = $progressed
    }
}

function Get-LoopDirective {
    param([string]$ResultText)

    $sectionText = Get-LoopControlSectionText -ResultText $ResultText

    if ([string]::IsNullOrWhiteSpace($sectionText)) {
        return [pscustomobject]@{
            LoopStatus       = "Continue"
            SelectionOutcome = ""
            NextTier         = ""
            StopReason       = ""
        }
    }

    $status = Get-DirectiveFieldValue -Text $sectionText -FieldName "LoopStatus"
    if ([string]::IsNullOrWhiteSpace($status)) {
        $status = "Continue"
    }

    return [pscustomobject]@{
        LoopStatus       = $status
        SelectionOutcome = Get-DirectiveFieldValue -Text $sectionText -FieldName "SelectionOutcome"
        NextTier         = Get-DirectiveFieldValue -Text $sectionText -FieldName "NextTier"
        StopReason       = Get-DirectiveFieldValue -Text $sectionText -FieldName "StopReason"
    }
}

function New-IterationPrompt {
    param(
        [Parameter(Mandatory = $true)][int]$Iteration,
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$RequirementsRoot,
        [Parameter(Mandatory = $true)][string]$TriagePath,
        [Parameter(Mandatory = $true)][string]$TriageScriptPath,
        [Parameter(Mandatory = $true)]$LoopPlan,
        [Parameter(Mandatory = $true)]$LoopStateDetails,
        [Parameter(Mandatory = $true)]$BeforeSnapshot,
        [Parameter(Mandatory = $true)]$BatchCandidates,
        [Parameter(Mandatory = $true)][int]$BatchTargetCount,
        [Parameter(Mandatory = $true)][int]$BatchMaxCount,
        [AllowNull()][string[]]$SectionPrefixAllowList = @()
    )

    $commitTail = @"

Before you finish:
- If you made any changes, create a local git commit for the work completed.
- If commit signing blocks the commit, retry with --no-gpg-sign.
- Do not leave useful work uncommitted.
- Do not commit temp files or generated triage files.
- If no files changed, say so explicitly.
"@

    $rfcOrderText = ($LoopPlan.RfcOrder -join " -> ")
    $tierOrderText = ($LoopPlan.TierOrder -join " -> ")
    $secondaryCheckedText = if ($LoopStateDetails.SecondaryRfcChecked) { "yes" } else { "no" }
    $hasMultipleRfcFoci = $LoopPlan.RfcOrder.Count -gt 1
    $batchCandidatesText = Format-RequirementBatchCandidates -BatchCandidates $BatchCandidates
    $batchCandidateCount = if ($null -ne $BatchCandidates -and $BatchCandidates.Requirements.Count -gt 0) { $BatchCandidates.Requirements.Count } else { 0 }
    $batchState = if ($null -ne $BatchCandidates) { $BatchCandidates.TriagedState } else { "" }
    $batchRfc = if ($null -ne $BatchCandidates) { $BatchCandidates.RequirementRfc } else { "" }
    $batchSection = if ($null -ne $BatchCandidates) { $BatchCandidates.SectionPrefix } else { "" }
    $batchSectionText = if ([string]::IsNullOrWhiteSpace($batchSection)) { "n/a" } else { $batchSection }
    $sectionPrefixFilterText = if ($null -ne $SectionPrefixAllowList -and $SectionPrefixAllowList.Count -gt 0) { ($SectionPrefixAllowList -join ", ") } else { "n/a" }

    return @"
You are helping systematically improve requirement-level test coverage and traceability in the quic-dotnet repository.

Iteration: $Iteration

Repository:
- Repo root: $RepoRoot
- Requirements root: $RequirementsRoot
- Current triage JSON: $TriagePath
- Triage regeneration script: $TriageScriptPath

Current triage summary before this iteration:
- $(Format-TriageSnapshot -Snapshot $BeforeSnapshot)

Operating model:
- We are converting the repo from broad, haphazard coverage into a requirement-centered proof model.
- Each requirement should have a canonical requirement-home file/class under tests/Incursa.Quic.Tests/RequirementHomes/<RFC>/ when focused proof is added.
- Canonical ownership is strict:
  - one file/class = one owning requirement
  - tests inside a canonical home should prove only that owning requirement
  - do not add extra Requirement IDs inside canonical requirement homes
- Existing broad tests may remain as supplemental proof, but should not be the primary proof artifact once focused proof exists.
- Requirement spec JSON is the source of truth for expected coverage dimensions.
- Trait("Category", ...) is the current evidence tag source because CoverageType is not yet broadly adopted.
- Requirement-home scaffolds without executable tests do not count as proof.
- Broad transport/frame codec aggregation tests and methods associated with more than six requirements are still broad proof.

Current loop state:
- Current RFC focus: $($LoopStateDetails.CurrentRfc)
- Current tier/mode: $($LoopStateDetails.CurrentTier) ($($LoopStateDetails.CurrentTierDescription))
- Next tier if the current tier is exhausted: $($LoopStateDetails.NextTier)
- RFC order: $rfcOrderText
- Tier order: $tierOrderText
- Secondary RFC already checked: $secondaryCheckedText
- Allowed section prefixes: $sectionPrefixFilterText
- Locked families: $($LoopPlan.LockedFamiliesNote)

Backlog categories:
- uncovered_unblocked: create new focused tests only where implementation exists
- All other states are out of scope for this runner.

Selection order inside the current RFC focus:
1. uncovered_unblocked

Global stopping rule:
- You MUST NOT return LoopStatus: Stop merely because the current preferred tier has no good batch.
- If the current RFC focus is exhausted, say so and continue with the next RFC focus.
- $(if ($hasMultipleRfcFoci) { "You may return LoopStatus: Stop only if uncovered_unblocked has been checked for the current RFC focus and at least one secondary RFC focus, and there is no remaining uncovered_unblocked batch anywhere outside the dead-end skip list." } else { "You may return LoopStatus: Stop only if the current RFC focus is exhausted and there is no remaining uncovered_unblocked batch in this lane outside the dead-end skip list." })
- If a batch has no implementation-backed proof seam but other uncovered_unblocked batches remain, return LoopStatus: Continue and a non-terminal SelectionOutcome.
- When you stop, SelectionOutcome must be RepoExhausted.

Avoid these families unless the triage clearly shows a real implementation-backed path:
- connection close / draining families
- stateful stateless-reset acceptance / lifecycle families
- blocked RFC9001 TLS / security families

Bounded-batch rules:
- Do not do repo-wide sweeps when a bounded batch is possible.
- Prefer a small adjacent cluster, usually 2 to 8 nearby requirements.
- Use the batch candidates below as the default work queue for this iteration.
- If the selected cluster has multiple nearby requirements that share the same helper, fixture, or seam, keep working through them in the same run.
- If a batch turns out to be a dead end, treat that as a local skip, not a terminal stop for the whole runner.
- Use old broad tests only as reference, setup inspiration, or helper extraction source.
- Do not mechanically move broad tests into requirement homes.
- Do not invent behavior.
- Do not silently change product code to make tests pass.
- Only make very small, low-risk testability seams if absolutely necessary.
- Preserve compileability.

Batch candidates from the current triage state:
- Triaged state: $batchState
- RFC focus: $batchRfc
- Section prefix: $batchSectionText
- Batch target count: $BatchTargetCount
- Batch maximum count: $BatchMaxCount
- Candidate count: $batchCandidateCount
- Candidates:
$batchCandidatesText

What you must do:
1. Read the current triage JSON first and treat it as the source of truth.
2. Stay in the current tier/mode for this run unless the current tier is exhausted.
3. If the current tier has no good batch, do not stop globally. Return the correct SelectionOutcome and advance to the next RFC focus.
4. If there is a good eligible batch:
   - execute one bounded batch
   - keep the work tightly scoped, but cover as many of the batch candidates as the shared proof seam safely allows
   - repair metadata first if applicable
   - otherwise add only missing proof dimensions for partials
   - otherwise narrow broad proof only where implementation clearly exists
   - otherwise add new focused tests only where implementation clearly exists
5. Run the smallest relevant test subset for touched files.
6. Regenerate the triage by running:
   pwsh -File "$TriageScriptPath"
7. Base your final report on the regenerated triage.

Required final output format:
## Decision
- Selected batch: <requirement ids or cluster name>
- Why this batch: <short reason>

## Files Changed
- ...

## Tests Run and Result
- ...

## Before/After State
- requirement id | before | after

## Loop Control
LoopStatus: Continue|Stop
SelectionOutcome: Worked|NoSliceInCurrentTier|NoSliceInCurrentRFC|RepoExhausted
NextTier: uncovered_unblocked|next_rfc|n/a
StopReason: n/a or reason

If there is no good eligible batch in the current tier, use SelectionOutcome to move to the next RFC focus.
Only use LoopStatus: Stop when SelectionOutcome is RepoExhausted.

$commitTail
"@
}

function Invoke-CodexIteration {
    param(
        [Parameter(Mandatory = $true)][string]$CodexExecutable,
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$Prompt,
        [Parameter(Mandatory = $true)][string]$ResultPath,
        [Parameter(Mandatory = $true)][string]$LogPath,
        [Parameter(Mandatory = $true)][string]$Sandbox,
        [Parameter(Mandatory = $true)][string]$Model,
        [Parameter(Mandatory = $true)][string]$ReasoningEffort
    )

    $process = $null
    $stdoutDone = $false
    $stderrDone = $false
    $stdoutTask = $null
    $stderrTask = $null
    $startTime = Get-Date
    $nextHeartbeatAt = $startTime.AddMinutes(5)

    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $CodexExecutable
        $psi.WorkingDirectory = $RepoRoot
        $psi.RedirectStandardInput = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true

        [void]$psi.ArgumentList.Add("exec")
        [void]$psi.ArgumentList.Add("--json")
        [void]$psi.ArgumentList.Add("--output-last-message")
        [void]$psi.ArgumentList.Add($ResultPath)
        [void]$psi.ArgumentList.Add("--sandbox")
        [void]$psi.ArgumentList.Add($Sandbox)
        [void]$psi.ArgumentList.Add("--model")
        [void]$psi.ArgumentList.Add($Model)
        [void]$psi.ArgumentList.Add("--config")
        [void]$psi.ArgumentList.Add("model_reasoning_effort=""$ReasoningEffort""")

        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $psi

        [void]$process.Start()

        $process.StandardInput.Write($Prompt)
        $process.StandardInput.Close()

        $stdoutTask = $process.StandardOutput.ReadLineAsync()
        $stderrTask = $process.StandardError.ReadLineAsync()

        while ($true) {
            $delayTask = [System.Threading.Tasks.Task]::Delay(250)
            $tasks = New-Object System.Collections.Generic.List[System.Threading.Tasks.Task]

            if (-not $stdoutDone) {
                [void]$tasks.Add([System.Threading.Tasks.Task]$stdoutTask)
            }

            if (-not $stderrDone) {
                [void]$tasks.Add([System.Threading.Tasks.Task]$stderrTask)
            }

            [void]$tasks.Add($delayTask)

            $completed = [System.Threading.Tasks.Task]::WhenAny($tasks.ToArray()).GetAwaiter().GetResult()

            if ($completed -eq $delayTask) {
                $now = Get-Date

                if ($now -ge $nextHeartbeatAt) {
                    $elapsed = $now - $startTime
                    Write-CodexStreamLine -StreamName "heartbeat" -Line "Codex still running after $($elapsed.ToString('hh\:mm\:ss'))" -LogPath $LogPath
                    $nextHeartbeatAt = $now.AddMinutes(5)
                }

                if ($process.HasExited -and $stdoutDone -and $stderrDone) {
                    break
                }

                continue
            }

            if (-not $stdoutDone -and $completed -eq $stdoutTask) {
                $line = $stdoutTask.GetAwaiter().GetResult()

                if ($null -eq $line) {
                    $stdoutDone = $true
                }
                else {
                    Write-CodexStreamLine -StreamName "stdout" -Line $line -LogPath $LogPath
                    $nextHeartbeatAt = (Get-Date).AddMinutes(5)
                    $stdoutTask = $process.StandardOutput.ReadLineAsync()
                }
            }
            elseif (-not $stderrDone -and $completed -eq $stderrTask) {
                $line = $stderrTask.GetAwaiter().GetResult()

                if ($null -eq $line) {
                    $stderrDone = $true
                }
                else {
                    Write-CodexStreamLine -StreamName "stderr" -Line $line -LogPath $LogPath
                    $nextHeartbeatAt = (Get-Date).AddMinutes(5)
                    $stderrTask = $process.StandardError.ReadLineAsync()
                }
            }

            if ($process.HasExited -and $stdoutDone -and $stderrDone) {
                break
            }
        }

        $process.WaitForExit()

        $endTime = Get-Date
        return [pscustomobject]@{
            ExitCode = $process.ExitCode
            Seconds  = [math]::Round(($endTime - $startTime).TotalSeconds, 2)
        }
    }
    finally {
        if ($null -ne $process) {
            try { $process.Dispose() } catch {}
        }
    }
}

try {
    $repoRoot = Resolve-ExistingPath -Path $RepoRoot
    $requirementsRoot = Resolve-ExistingPath -Path $RequirementsRoot
    $triagePath = Resolve-ExistingPath -Path $TriagePath
    $triageScriptPath = Resolve-ExistingPath -Path $TriageScriptPath
    $codexExecutable = Resolve-CodexCommand -Command $CodexCommand
    $loopPlan = Get-LoopPlan -RfcOrder $RfcOrder
    $loopState = New-LoopState

    $outputRoot = Ensure-Directory -Path $OutputDirectory
    $resultsRoot = Ensure-Directory -Path (Join-Path $outputRoot "results")
    $logsRoot = Ensure-Directory -Path (Join-Path $outputRoot "logs")
    $deadEndSkipPath = Join-Path $outputRoot "dead-end-batches.txt"
    $deadEndBatchKeys = Read-LineList -Path $deadEndSkipPath

    $summaryRows = New-Object System.Collections.Generic.List[object]
    $beforeSnapshot = Get-TriageSnapshot -Path $triagePath
    $noProgressCount = 0

    Write-Host ""
    Write-Host "Initial triage: $(Format-TriageSnapshot -Snapshot $beforeSnapshot)" -ForegroundColor Green

    for ($iteration = 1; $iteration -le $MaxIterations; $iteration++) {
        Write-Host ""
        Write-Host "=== Iteration $iteration / $MaxIterations ===" -ForegroundColor White

        $resultPath = Join-Path $resultsRoot ("iteration-{0:D3}.output.md" -f $iteration)
        $logPath = Join-Path $logsRoot ("iteration-{0:D3}.log.txt" -f $iteration)
        $loopStateDetails = Get-LoopStateDetails -LoopPlan $loopPlan -LoopState $loopState
        $batchCandidates = Get-RequirementBatchCandidates `
            -TriagePath $triagePath `
            -CurrentRfcFocus $loopStateDetails.CurrentRfc `
            -CurrentTier $loopStateDetails.CurrentTier `
            -TargetCount $BatchTargetCount `
            -MaxCount $BatchMaxCount `
            -SectionPrefixAllowList $SectionPrefixAllowList `
            -ExcludedBatchKeys $deadEndBatchKeys

        $batchRequirementIds = if ($null -ne $batchCandidates -and $batchCandidates.Requirements.Count -gt 0) {
            ($batchCandidates.Requirements | ForEach-Object { $_.RequirementId }) -join ", "
        }
        else {
            ""
        }

        $batchDisposition = "Selected"
        $skipRun = $false
        $syntheticDirective = $null

        if ($null -eq $batchCandidates -or $batchCandidates.Requirements.Count -eq 0) {
            $batchDisposition = "NoCandidates"
            $skipRun = $true
            $syntheticDirective = [pscustomobject]@{
                LoopStatus       = "Continue"
                SelectionOutcome = "NoSliceInCurrentRFC"
                NextTier         = "next_rfc"
                StopReason       = ""
            }
            Write-Warning "No unskipped uncovered_unblocked batch candidates remain for $($loopStateDetails.CurrentRfc); advancing to the next RFC focus."
        }
        elseif ([string]::IsNullOrWhiteSpace($batchRequirementIds)) {
            Write-Host "Batch: none preselected" -ForegroundColor DarkCyan
        }
        else {
            Write-Host "Batch: $($batchCandidates.RequirementRfc) / $($batchCandidates.SectionPrefix) / $batchRequirementIds" -ForegroundColor DarkCyan
        }

        $run = $null
        $status = "Success"
        $stopNow = $false
        $stopReason = ""

        if (-not $skipRun) {
            $prompt = New-IterationPrompt `
                -Iteration $iteration `
                -RepoRoot $repoRoot `
                -RequirementsRoot $requirementsRoot `
                -TriagePath $triagePath `
                -TriageScriptPath $triageScriptPath `
                -LoopPlan $loopPlan `
                -LoopStateDetails $loopStateDetails `
                -BeforeSnapshot $beforeSnapshot `
                -BatchCandidates $batchCandidates `
                -BatchTargetCount $BatchTargetCount `
                -BatchMaxCount $BatchMaxCount `
                -SectionPrefixAllowList $SectionPrefixAllowList

            try {
                $run = Invoke-CodexIteration `
                    -CodexExecutable $codexExecutable `
                    -RepoRoot $repoRoot `
                    -Prompt $prompt `
                    -ResultPath $resultPath `
                    -LogPath $logPath `
                    -Sandbox $Sandbox `
                    -Model $Model `
                    -ReasoningEffort $ReasoningEffort

                if ($run.ExitCode -ne 0) {
                    $status = "Failed"
                    $stopNow = $true
                    $stopReason = "Codex exited with code $($run.ExitCode)."
                }
            }
            catch {
                $status = "Exception"
                $detail = Get-ExceptionDetail -Exception $_.Exception
                $logDirectory = Split-Path -Path $logPath -Parent
                if (-not [string]::IsNullOrWhiteSpace($logDirectory)) {
                    Ensure-Directory -Path $logDirectory | Out-Null
                }
                [System.IO.File]::AppendAllText($logPath, "[exception] $($_ | Out-String)$([Environment]::NewLine)")
                $run = [pscustomobject]@{ ExitCode = -1; Seconds = 0 }
                $stopNow = $true
                $stopReason = "Exception while running Codex: $detail"
            }
        }

        $afterSnapshot = Get-TriageSnapshot -Path $triagePath

        if ($skipRun) {
            $directive = $syntheticDirective
            $transition = Resolve-LoopTransition -LoopPlan $loopPlan -LoopState $loopState -Directive $directive -HasCurrentBatchCandidates $false
            $run = [pscustomobject]@{ ExitCode = 0; Seconds = 0 }
            $status = "Skipped"
            $stopNow = $transition.ShouldStop
            $stopReason = if ($stopNow) { $transition.StopReason } else { "No unskipped uncovered_unblocked batches remain in $($loopStateDetails.CurrentRfc)." }
            $batchDisposition = "NoCandidates"
        }
        else {
            $resultText = if (Test-Path -LiteralPath $resultPath) { Get-Content -LiteralPath $resultPath -Raw } else { "" }
            $directive = Get-LoopDirective -ResultText $resultText
            $transition = Resolve-LoopTransition -LoopPlan $loopPlan -LoopState $loopState -Directive $directive -HasCurrentBatchCandidates ($batchCandidates.Requirements.Count -gt 0)

            $remainingEligibleUncovered = $false
            if ($transition.EffectiveSelectionOutcome -eq "RepoExhausted" -and $batchCandidates.Requirements.Count -gt 0) {
                $remainingEligibleUncovered = Test-HasRemainingEligibleUncoveredBatch -TriagePath $triagePath -SectionPrefixAllowList $SectionPrefixAllowList -ExcludedBatchKeys $deadEndBatchKeys
            }

            if ($transition.EffectiveSelectionOutcome -eq "RepoExhausted" -and $batchCandidates.Requirements.Count -gt 0 -and ((Test-IsDeadEndStopReason -StopReason $transition.StopReason) -or $remainingEligibleUncovered)) {
                $deadEndKey = $batchCandidates.BatchKey
                if (-not ($deadEndBatchKeys -contains $deadEndKey)) {
                    $deadEndBatchKeys = Add-LineIfMissing -Lines $deadEndBatchKeys -Line $deadEndKey
                    Write-LineList -Path $deadEndSkipPath -Lines $deadEndBatchKeys
                }

                $batchDisposition = "DeadEndSkipped"
                $status = "Skipped"
                $stopNow = $false
                $stopReason = if (Test-IsDeadEndStopReason -StopReason $transition.StopReason) {
                    "Skipping dead-end batch $deadEndKey and continuing with uncovered_unblocked."
                }
                else {
                    "Skipping RepoExhausted batch $deadEndKey because uncovered_unblocked work remains elsewhere."
                }
                $transition = [pscustomobject]@{
                    DirectiveLoopStatus       = $directive.LoopStatus
                    DirectiveSelectionOutcome = $directive.SelectionOutcome
                    DirectiveNextTier         = if ([string]::IsNullOrWhiteSpace($directive.NextTier)) { "" } else { $directive.NextTier.Trim() }
                    DirectiveStopReason       = $directive.StopReason
                    EffectiveLoopStatus       = "Continue"
                    EffectiveSelectionOutcome = "BatchDeadEndSkipped"
                    EffectiveNextTier         = "uncovered_unblocked"
                    NextState                 = $loopState
                    NextStateDetails          = $loopStateDetails
                    ShouldStop                = $false
                    StopReason                = $stopReason
                    Progressed                = $true
                }
            }
        }

        $triageChanged = $afterSnapshot.Fingerprint -ne $beforeSnapshot.Fingerprint
        if ($triageChanged -or $transition.Progressed) {
            $noProgressCount = 0
        }
        else {
            $noProgressCount++
        }

        $stalledBatchSkipped = $false
        if (-not $stopNow -and $transition.ShouldStop) {
            $stopNow = $true
            $stopReason = $transition.StopReason
        }
        elseif (-not $stopNow -and $directive.LoopStatus -eq "Stop" -and $batchDisposition -ne "DeadEndSkipped") {
            Write-Warning "Ignoring premature LoopStatus: Stop because SelectionOutcome was '$($transition.DirectiveSelectionOutcome)' and the current loop state still has eligible lanes."
        }

        if (-not $stopNow -and $noProgressCount -ge $NoProgressLimit) {
            if ($null -ne $batchCandidates -and $batchCandidates.Requirements.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($batchCandidates.BatchKey)) {
                $stalledBatchKey = $batchCandidates.BatchKey
                if (-not ($deadEndBatchKeys -contains $stalledBatchKey)) {
                    $deadEndBatchKeys = Add-LineIfMissing -Lines $deadEndBatchKeys -Line $stalledBatchKey
                    Write-LineList -Path $deadEndSkipPath -Lines $deadEndBatchKeys
                }

                $batchDisposition = "NoProgressSkipped"
                $status = "Skipped"
                $stopReason = "Skipping stalled batch $stalledBatchKey after $noProgressCount consecutive no-progress iteration(s) and continuing with uncovered_unblocked."
                $transition = [pscustomobject]@{
                    DirectiveLoopStatus       = $directive.LoopStatus
                    DirectiveSelectionOutcome = $directive.SelectionOutcome
                    DirectiveNextTier         = if ([string]::IsNullOrWhiteSpace($directive.NextTier)) { "" } else { $directive.NextTier.Trim() }
                    DirectiveStopReason       = $directive.StopReason
                    EffectiveLoopStatus       = "Continue"
                    EffectiveSelectionOutcome = "BatchNoProgressSkipped"
                    EffectiveNextTier         = "uncovered_unblocked"
                    NextState                 = $loopState
                    NextStateDetails          = $loopStateDetails
                    ShouldStop                = $false
                    StopReason                = $stopReason
                    Progressed                = $true
                }
                $stalledBatchSkipped = $true
            }
            else {
                $stopNow = $true
                $stopReason = "Triage fingerprint did not change for $noProgressCount consecutive iteration(s), and no batch candidate could be skipped."
            }
        }

        $iterationOutcomeKind = Get-IterationOutcomeKind `
            -Status $status `
            -BatchDisposition $batchDisposition `
            -StopNow $stopNow `
            -SelectionOutcome $transition.EffectiveSelectionOutcome `
            -TriageChanged $triageChanged `
            -Progressed $transition.Progressed

        $summaryRows.Add([pscustomobject]@{
            Iteration         = $iteration
            Status            = $status
            OutcomeKind       = $iterationOutcomeKind
            ExitCode          = $run.ExitCode
            Seconds           = $run.Seconds
            Before            = (Format-TriageSnapshot -Snapshot $beforeSnapshot)
            After             = (Format-TriageSnapshot -Snapshot $afterSnapshot)
            TriageChanged     = $triageChanged
            NoProgressCount   = $noProgressCount
            ResultFile        = $resultPath
            LogFile           = $logPath
            CurrentRFC        = $loopStateDetails.CurrentRfc
            CurrentTier       = $loopStateDetails.CurrentTier
            BatchDisposition  = $batchDisposition
            BatchTriagedState = if ($null -ne $batchCandidates) { $batchCandidates.TriagedState } else { "" }
            BatchTargetCount  = $BatchTargetCount
            BatchMaxCount     = $BatchMaxCount
            BatchCandidateCount = if ($null -ne $batchCandidates -and $batchCandidates.Requirements.Count -gt 0) { $batchCandidates.Requirements.Count } else { 0 }
            BatchSectionPrefix = if ($null -ne $batchCandidates) { $batchCandidates.SectionPrefix } else { "" }
            BatchRequirementIds = $batchRequirementIds
            DirectiveLoopStatus = $transition.DirectiveLoopStatus
            DirectiveSelectionOutcome = $transition.DirectiveSelectionOutcome
            DirectiveNextTier = $transition.DirectiveNextTier
            SelectionOutcome  = $transition.EffectiveSelectionOutcome
            NextTier          = $transition.EffectiveNextTier
            LoopStatus        = $transition.EffectiveLoopStatus
            StopReason        = $stopReason
        })

        Write-Host "Before: $(Format-TriageSnapshot -Snapshot $beforeSnapshot)" -ForegroundColor DarkGray
        Write-Host "After : $(Format-TriageSnapshot -Snapshot $afterSnapshot)" -ForegroundColor DarkGray

        if ($stopNow) {
            Write-Host ""
            Write-Warning "Stopping after iteration $iteration. $stopReason"
            break
        }

        if ($stalledBatchSkipped) {
            $noProgressCount = 0
        }

        $beforeSnapshot = $afterSnapshot
        $loopState = $transition.NextState

        if ($CooldownSeconds -gt 0 -and $iteration -lt $MaxIterations) {
            Start-Sleep -Seconds $CooldownSeconds
        }
    }

    $summaryPath = Join-Path $outputRoot "summary.csv"
    $summaryRows | Export-Csv -LiteralPath $summaryPath -NoTypeInformation

    Write-Host ""
    if ($summaryRows.Count -gt 0) {
        Write-Host "Iteration outcome breakdown:" -ForegroundColor Green
        foreach ($group in ($summaryRows | Group-Object -Property OutcomeKind | Sort-Object Name)) {
            Write-Host "  $($group.Name): $($group.Count)"
        }
        $finalOutcome = $summaryRows[$summaryRows.Count - 1]
        Write-Host "Final outcome: $($finalOutcome.OutcomeKind)" -ForegroundColor Green
        if (-not [string]::IsNullOrWhiteSpace($finalOutcome.StopReason)) {
            Write-Host "Final stop reason: $($finalOutcome.StopReason)" -ForegroundColor Green
        }
    }

    Write-Host "Done." -ForegroundColor Green
    Write-Host "Repo root:  $repoRoot"
    Write-Host "Triage:     $triagePath"
    Write-Host "Results:    $resultsRoot"
    Write-Host "Logs:       $logsRoot"
    Write-Host "Summary:    $summaryPath"
}
catch {
    Write-Error ($_ | Out-String)
    exit 1
}
