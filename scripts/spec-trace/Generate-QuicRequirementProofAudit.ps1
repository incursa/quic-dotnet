[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path,
    [string]$CoverageTriageJsonPath = "",
    [string]$OutputJsonPath = "",
    [string]$OutputMarkdownPath = "",
    [switch]$FailOnMissingRequired,
    [switch]$FailOnDeferred
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($CoverageTriageJsonPath))
{
    $CoverageTriageJsonPath = Join-Path $RepoRoot "specs\generated\quic\quic-requirement-coverage-triage.json"
}

if ([string]::IsNullOrWhiteSpace($OutputJsonPath))
{
    $OutputJsonPath = Join-Path $RepoRoot "specs\generated\quic\quic-requirement-proof-audit.json"
}

if ([string]::IsNullOrWhiteSpace($OutputMarkdownPath))
{
    $OutputMarkdownPath = Join-Path $RepoRoot "specs\generated\quic\quic-requirement-proof-audit.md"
}

function ConvertTo-StringArray {
    param([object]$Value)

    $values = New-Object System.Collections.Generic.List[string]
    foreach ($item in @($Value))
    {
        if ($null -eq $item)
        {
            continue
        }

        $text = $item.ToString()
        if (-not [string]::IsNullOrWhiteSpace($text))
        {
            $values.Add($text)
        }
    }

    return @($values)
}

function Get-ExpectationValue {
    param(
        [object]$Expectations,
        [string]$Kind
    )

    if ($null -eq $Expectations -or -not ($Expectations.PSObject.Properties.Name -contains $Kind))
    {
        return "optional"
    }

    $value = $Expectations.$Kind
    if ($null -eq $value)
    {
        return "optional"
    }

    return $value.ToString().ToLowerInvariant()
}

function Add-Count {
    param(
        [hashtable]$Table,
        [string]$Key
    )

    if (-not $Table.ContainsKey($Key))
    {
        $Table[$Key] = 0
    }

    $Table[$Key] = [int]$Table[$Key] + 1
}

function ConvertTo-OrderedCountObject {
    param([hashtable]$Table)

    $ordered = [ordered]@{}
    foreach ($key in @($Table.Keys | Sort-Object))
    {
        $ordered[$key] = $Table[$key]
    }

    return [pscustomobject]$ordered
}

function Test-FocusedExecutableEvidence {
    param([object]$Evidence)

    if ($null -eq $Evidence -or [string]::IsNullOrWhiteSpace($Evidence.method))
    {
        return $false
    }

    if ($Evidence.source -eq "spec_xref" -and
        -not [string]::IsNullOrWhiteSpace($Evidence.x_test_ref) -and
        $Evidence.file -match '(^|[\\/])RequirementHomes[\\/]')
    {
        return $true
    }

    return $Evidence.strength -eq "focused"
}

$triage = Get-Content -Raw -LiteralPath $CoverageTriageJsonPath | ConvertFrom-Json
$requirements = @($triage.requirements)

$auditRows = New-Object System.Collections.Generic.List[object]
$stateCounts = @{}
$rfcCounts = @{}

foreach ($requirement in $requirements)
{
    $focusedMethodEvidence = @($requirement.evidence | Where-Object {
            Test-FocusedExecutableEvidence $_
        })

    $focusedKinds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $broadKinds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $methodNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $focusedFiles = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($evidence in @($requirement.evidence))
    {
        $kinds = ConvertTo-StringArray $evidence.kinds
        if (Test-FocusedExecutableEvidence $evidence)
        {
            foreach ($kind in $kinds)
            {
                [void]$focusedKinds.Add($kind.ToLowerInvariant())
            }

            [void]$methodNames.Add($evidence.member)
            [void]$focusedFiles.Add($evidence.file)
            continue
        }

        foreach ($kind in $kinds)
        {
            [void]$broadKinds.Add($kind.ToLowerInvariant())
        }
    }

    $requiredKinds = New-Object System.Collections.Generic.List[string]
    $deferredKinds = New-Object System.Collections.Generic.List[string]
    foreach ($kind in @("positive", "negative", "edge", "fuzz", "benchmark"))
    {
        $expectation = Get-ExpectationValue $requirement.coverage_expectations $kind
        if ($expectation -eq "required")
        {
            $requiredKinds.Add($kind)
        }
        elseif ($expectation -eq "deferred")
        {
            $deferredKinds.Add($kind)
        }
    }

    $missingRequiredFocusedKinds = New-Object System.Collections.Generic.List[string]
    foreach ($kind in $requiredKinds)
    {
        if (-not $focusedKinds.Contains($kind))
        {
            $missingRequiredFocusedKinds.Add($kind)
        }
    }

    $missingDeferredFocusedKinds = New-Object System.Collections.Generic.List[string]
    foreach ($kind in $deferredKinds)
    {
        if (-not $focusedKinds.Contains($kind))
        {
            $missingDeferredFocusedKinds.Add($kind)
        }
    }

    $state = "full_executable_proof"
    $queue = New-Object System.Collections.Generic.List[string]

    if ($focusedMethodEvidence.Count -eq 0)
    {
        $state = "no_focused_executable_proof"
        $queue.Add("add_requirement_home_tests")
    }
    elseif ($missingRequiredFocusedKinds.Count -gt 0)
    {
        $state = "missing_required_focused_proof"
        foreach ($kind in $missingRequiredFocusedKinds)
        {
            $queue.Add("add_$($kind)_proof")
        }
    }
    elseif ($missingDeferredFocusedKinds.Count -gt 0)
    {
        $state = "deferred_proof_not_executed"
        foreach ($kind in $missingDeferredFocusedKinds)
        {
            $queue.Add("consider_$($kind)_proof")
        }
    }

    if ($queue.Count -eq 0)
    {
        $queue.Add("clean")
    }

    Add-Count $stateCounts $state
    if (-not $rfcCounts.ContainsKey($requirement.rfc))
    {
        $rfcCounts[$requirement.rfc] = @{}
    }

    Add-Count $rfcCounts[$requirement.rfc] $state

    $auditRows.Add([pscustomobject]@{
            requirement_id                 = $requirement.requirement_id
            rfc                            = $requirement.rfc
            title                          = $requirement.title
            statement                      = $requirement.statement
            proof_state                    = $state
            work_queue_tags                = @($queue)
            required_kinds                 = @($requiredKinds)
            deferred_kinds                 = @($deferredKinds)
            focused_kinds                  = @($focusedKinds | Sort-Object)
            broad_kinds                    = @($broadKinds | Sort-Object)
            missing_required_focused_kinds = @($missingRequiredFocusedKinds)
            missing_deferred_focused_kinds = @($missingDeferredFocusedKinds)
            focused_method_count           = $methodNames.Count
            focused_file_count             = $focusedFiles.Count
            focused_files                  = @($focusedFiles | Sort-Object)
            spec_test_ref_count            = $requirement.spec_test_ref_count
            spec_test_refs                 = $requirement.spec_test_refs
        })
}

$byRfc = New-Object System.Collections.Generic.List[object]
foreach ($rfc in @($rfcCounts.Keys | Sort-Object))
{
    $total = 0
    foreach ($value in $rfcCounts[$rfc].Values)
    {
        $total += [int]$value
    }

    $byRfc.Add([pscustomobject]@{
            rfc            = $rfc
            total          = $total
            by_proof_state = (ConvertTo-OrderedCountObject $rfcCounts[$rfc])
        })
}

$summary = [pscustomobject]@{
    generated_at       = (Get-Date).ToString("o")
    repo_root          = $RepoRoot
    source_triage      = [System.IO.Path]::GetRelativePath($RepoRoot, $CoverageTriageJsonPath).Replace("\", "/")
    total_requirements = $requirements.Count
    by_proof_state     = (ConvertTo-OrderedCountObject $stateCounts)
    by_rfc             = @($byRfc.ToArray())
}

$report = [pscustomobject]@{
    schema_version = 1
    summary        = $summary
    requirements   = @($auditRows.ToArray())
}

$outputDirectory = Split-Path -Parent $OutputJsonPath
if (-not [string]::IsNullOrWhiteSpace($outputDirectory))
{
    New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null
}

$report | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $OutputJsonPath -Encoding utf8

$markdown = New-Object System.Collections.Generic.List[string]
$markdown.Add("# QUIC Requirement Proof Audit")
$markdown.Add("")
$markdown.Add("This report is stricter than trace coverage. It only counts focused executable method-level evidence toward required proof dimensions.")
$markdown.Add("")
$markdown.Add("## Summary")
$markdown.Add("")
$markdown.Add("| Proof state | Count |")
$markdown.Add("| --- | ---: |")
foreach ($key in @($stateCounts.Keys | Sort-Object))
{
    $markdown.Add("| $key | $($stateCounts[$key]) |")
}

$markdown.Add("")
$markdown.Add("## RFC Breakdown")
$markdown.Add("")
$markdown.Add("| RFC | Total | full_executable_proof | missing_required_focused_proof | deferred_proof_not_executed | no_focused_executable_proof |")
$markdown.Add("| --- | ---: | ---: | ---: | ---: | ---: |")
foreach ($rfc in @($rfcCounts.Keys | Sort-Object))
{
    $counts = $rfcCounts[$rfc]
    $total = 0
    foreach ($value in $counts.Values)
    {
        $total += [int]$value
    }

    $markdown.Add("| $rfc | $total | $($counts['full_executable_proof'] ?? 0) | $($counts['missing_required_focused_proof'] ?? 0) | $($counts['deferred_proof_not_executed'] ?? 0) | $($counts['no_focused_executable_proof'] ?? 0) |")
}

$examples = @($auditRows | Where-Object { $_.proof_state -ne "full_executable_proof" } | Sort-Object rfc, requirement_id | Select-Object -First 50)
$markdown.Add("")
$markdown.Add("## First Non-Full-Proof Items")
$markdown.Add("")
if ($examples.Count -eq 0)
{
    $markdown.Add("No non-full-proof items.")
}
else
{
    $markdown.Add("| Requirement | RFC | Proof state | Missing required | Deferred missing |")
    $markdown.Add("| --- | --- | --- | --- | --- |")
    foreach ($row in $examples)
    {
        $requirementId = $row.requirement_id
        $missingRequired = [string]::Join(', ', @($row.missing_required_focused_kinds))
        $missingDeferred = [string]::Join(', ', @($row.missing_deferred_focused_kinds))
        $markdown.Add("| ``$requirementId`` | $($row.rfc) | $($row.proof_state) | $missingRequired | $missingDeferred |")
    }
}

$markdown | Set-Content -LiteralPath $OutputMarkdownPath -Encoding utf8

Write-Host "Wrote $OutputJsonPath"
Write-Host "Wrote $OutputMarkdownPath"

$missingRequiredCount = if ($stateCounts.ContainsKey("missing_required_focused_proof")) { [int]$stateCounts["missing_required_focused_proof"] } else { 0 }
$deferredCount = if ($stateCounts.ContainsKey("deferred_proof_not_executed")) { [int]$stateCounts["deferred_proof_not_executed"] } else { 0 }

if ($FailOnMissingRequired -and $missingRequiredCount -gt 0)
{
    throw "Requirement proof audit found $missingRequiredCount requirement(s) missing required focused proof."
}

if ($FailOnDeferred -and $deferredCount -gt 0)
{
    throw "Requirement proof audit found $deferredCount requirement(s) with deferred proof not executed."
}
