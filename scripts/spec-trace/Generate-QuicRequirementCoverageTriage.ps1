[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path,
    [string]$OutputJsonPath = "",
    [string]$OutputMarkdownPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($OutputJsonPath))
{
    $OutputJsonPath = Join-Path $RepoRoot "specs\generated\quic\quic-requirement-coverage-triage.json"
}

if ([string]::IsNullOrWhiteSpace($OutputMarkdownPath))
{
    $OutputMarkdownPath = Join-Path $RepoRoot "specs\generated\quic\quic-requirement-coverage-triage.md"
}

function Get-RelativeRepoPath {
    param([string]$Path)

    return [System.IO.Path]::GetRelativePath($RepoRoot, $Path).Replace("\", "/")
}

function Get-RequirementSectionPrefix {
    param([string]$RequirementId)

    if ($RequirementId -match '^REQ-QUIC-RFC\d+-(?<prefix>S[A-Z0-9P]+)-\d{4}$')
    {
        return $Matches.prefix
    }

    throw "Unable to derive section prefix from requirement id '$RequirementId'."
}

function ConvertTo-RequirementEvidenceKind {
    param(
        [string[]]$Categories,
        [string]$FilePath
    )

    $kindSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($category in $Categories)
    {
        switch -Regex ($category)
        {
            '^positive$' { [void]$kindSet.Add('positive') }
            '^negative$' { [void]$kindSet.Add('negative') }
            '^edge$' { [void]$kindSet.Add('edge') }
            '^property$' { [void]$kindSet.Add('edge') }
            '^fuzz$' { [void]$kindSet.Add('fuzz') }
            '^benchmark$' { [void]$kindSet.Add('benchmark') }
            default { }
        }
    }

    if ($kindSet.Count -eq 0)
    {
        if ($FilePath -match 'FuzzTests\.cs$')
        {
            [void]$kindSet.Add('fuzz')
        }
        elseif ($FilePath -match 'PropertyTests\.cs$')
        {
            [void]$kindSet.Add('edge')
        }
    }

    if ($kindSet.Count -eq 0)
    {
        [void]$kindSet.Add('unspecified')
    }

    return @($kindSet | Sort-Object)
}

function Get-EvidenceStrength {
    param(
        [int]$AssociatedRequirementCount,
        [bool]$IsClassLevelOnly,
        [string]$FilePath
    )

    if ($FilePath -match '(^|[\\/])RequirementHomes[\\/]' -and $AssociatedRequirementCount -eq 1)
    {
        return 'focused'
    }

    if ($IsClassLevelOnly)
    {
        return 'broad'
    }

    if ($AssociatedRequirementCount -gt 6)
    {
        return 'broad'
    }

    if ($FilePath -match 'QuicTransportParametersTests\.cs$' -or
        $FilePath -match 'QuicFrameCodecPart[34]Tests\.cs$')
    {
        return 'broad'
    }

    return 'focused'
}

function Parse-AttributeBlock {
    param([string[]]$Lines)

    $attributes = @()
    $index = 0
    while ($index -lt $Lines.Count)
    {
        $line = $Lines[$index].Trim()
        if (-not $line.StartsWith('['))
        {
            $index++
            continue
        }

        $builder = [System.Text.StringBuilder]::new()
        while ($true)
        {
            $current = $Lines[$index].Trim()
            [void]$builder.Append($current)
            if ($current.EndsWith(']'))
            {
                break
            }

            $index++
            if ($index -ge $Lines.Count)
            {
                break
            }
        }

        $text = $builder.ToString()
        if ($text -match '^\[(?<name>[A-Za-z_][A-Za-z0-9_]*)')
        {
            $attributeName = $Matches.name
            $arguments = if ($text -match '^\[[^(]+\((?<args>.*)\)\]$') { $Matches.args } else { '' }
            $attributes += [pscustomobject]@{
                Name      = $attributeName
                Text      = $text
                Arguments = $arguments
            }
        }

        $index++
    }

    return $attributes
}

function Get-RequirementsFromAttributes {
    param($Attributes)

    $ids = [System.Collections.Generic.List[string]]::new()
    foreach ($attribute in $Attributes)
    {
        if ($attribute.Name -ne 'Requirement')
        {
            continue
        }

        foreach ($match in [regex]::Matches($attribute.Text, 'REQ-QUIC-RFC\d+-S[A-Z0-9P]+-\d{4}'))
        {
            $ids.Add($match.Value)
        }
    }

    return @($ids | Sort-Object -Unique)
}

function Get-CategoriesFromAttributes {
    param($Attributes)

    $categories = [System.Collections.Generic.List[string]]::new()
    foreach ($attribute in $Attributes)
    {
        if ($attribute.Name -eq 'Trait' -and $attribute.Text -match 'Trait\("Category"\s*,\s*"(?<value>[^"]+)"\)')
        {
            $categories.Add($Matches.value)
            continue
        }

        if ($attribute.Name -eq 'CoverageType')
        {
            foreach ($match in [regex]::Matches($attribute.Text, 'RequirementCoverageType\.(?<kind>[A-Za-z]+)'))
            {
                $categories.Add($match.Groups['kind'].Value)
            }
        }
    }

    return @($categories | Sort-Object -Unique)
}

function Get-TestMethodRecords {
    param([string]$TestsRoot)

    $records = [System.Collections.Generic.List[object]]::new()
    $files = Get-ChildItem -Path $TestsRoot -Filter '*.cs' -File -Recurse |
        Where-Object { $_.FullName -notmatch '\\bin\\|\\obj\\' }

    foreach ($file in $files)
    {
        $lines = @(Get-Content $file.FullName)
        $pendingAttributeLines = [System.Collections.Generic.List[string]]::new()
        $classStack = [System.Collections.Generic.Stack[object]]::new()
        $braceDepth = 0

        for ($index = 0; $index -lt $lines.Count; $index++)
        {
            $line = $lines[$index]
            $trimmed = $line.Trim()
            $pushedClass = $false

            if ([string]::IsNullOrWhiteSpace($trimmed))
            {
                continue
            }

            if ($trimmed.StartsWith('['))
            {
                $pendingAttributeLines.Add($line)
                continue
            }

            if ($trimmed.StartsWith('///') -or
                $trimmed.StartsWith('//') -or
                $trimmed.StartsWith('/*') -or
                $trimmed.StartsWith('*') -or
                $trimmed.StartsWith('*/'))
            {
                continue
            }

            if ($trimmed -match '^(?:public|internal|private|protected)?\s*(?:sealed\s+|static\s+|abstract\s+|partial\s+)*class\s+(?<name>[A-Za-z_][A-Za-z0-9_]*)')
            {
                $classAttributes = Parse-AttributeBlock -Lines @($pendingAttributeLines)
                $pendingAttributeLines.Clear()

                $classStack.Push([pscustomobject]@{
                        Name         = $Matches.name
                        Requirements = @(Get-RequirementsFromAttributes -Attributes $classAttributes)
                        Categories   = @(Get-CategoriesFromAttributes -Attributes $classAttributes)
                        BraceDepth   = $braceDepth
                    })
                $pushedClass = $true
            }
            elseif ($trimmed -match '^(?:public|internal|private|protected)\s+(?:async\s+)?(?:static\s+)?(?:override\s+)?(?:unsafe\s+)?(?:[A-Za-z0-9_<>\[\]\.?]+)\s+(?<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(')
            {
                $methodAttributes = Parse-AttributeBlock -Lines @($pendingAttributeLines)
                $pendingAttributeLines.Clear()

                $currentClass = if ($classStack.Count -gt 0) { $classStack.Peek() } else { $null }
                $classRequirements = if ($null -ne $currentClass) { @($currentClass.Requirements) } else { @() }
                $classCategories = if ($null -ne $currentClass) { @($currentClass.Categories) } else { @() }
                $className = if ($null -ne $currentClass) { $currentClass.Name } else { $null }
                $methodRequirements = @(Get-RequirementsFromAttributes -Attributes $methodAttributes)
                $combinedRequirementIds = @($classRequirements) + @($methodRequirements)
                $combinedRequirements = @($combinedRequirementIds | Sort-Object -Unique)
                $methodCategories = @(Get-CategoriesFromAttributes -Attributes $methodAttributes)
                $combinedCategoryNames = @($classCategories) + @($methodCategories)
                $combinedCategories = @($combinedCategoryNames | Sort-Object -Unique)
                $methodAttributeNames = @($methodAttributes | ForEach-Object { $_.Name })
                $isTestMethod = ($methodAttributeNames -contains 'Fact') -or ($methodAttributeNames -contains 'Theory')
                $isClassLevelOnly = (@($methodRequirements).Count -eq 0 -and @($classRequirements).Count -gt 0)

                if ($isTestMethod)
                {
                    $records.Add([pscustomobject]@{
                            FilePath                    = $file.FullName
                            RepoPath                    = Get-RelativeRepoPath -Path $file.FullName
                            ClassName                   = $className
                            MethodName                  = $Matches.name
                            LineNumber                  = $index + 1
                            MethodRequirementIds        = $methodRequirements
                            ClassRequirementIds         = $classRequirements
                            RequirementIds              = $combinedRequirements
                            Categories                  = $combinedCategories
                            MethodCategories            = $methodCategories
                            EvidenceKinds               = @(ConvertTo-RequirementEvidenceKind -Categories $combinedCategories -FilePath $file.FullName)
                            IsClassLevelOnly            = $isClassLevelOnly
                            AssociatedRequirementCount  = @($combinedRequirements).Count
                            EvidenceStrength            = Get-EvidenceStrength -AssociatedRequirementCount @($combinedRequirements).Count -IsClassLevelOnly $isClassLevelOnly -FilePath $file.FullName
                            FullyQualifiedMember        = if ($null -ne $currentClass) { "$($currentClass.Name).$($Matches.name)" } else { $Matches.name }
                        })
                }
            }
            else
            {
                $pendingAttributeLines.Clear()
            }

            $openBraces = ([regex]::Matches($line, '\{')).Count
            $closeBraces = ([regex]::Matches($line, '\}')).Count
            $braceDepth += $openBraces - $closeBraces

            while (-not $pushedClass -and $classStack.Count -gt 0 -and $braceDepth -le $classStack.Peek().BraceDepth)
            {
                [void]$classStack.Pop()
            }
        }
    }

    return $records
}

function Get-RequirementGapMappings {
    param([string]$GapPath)

    $gapContent = Get-Content $GapPath -Raw

    return @(
        [pscustomobject]@{
            Slug               = '9000-19-retransmission-and-frame-reliability'
            Summary            = 'Remaining RFC 9000 Section 13.3 retransmission and loss-signaling requirements depend on a sender/recovery architecture.'
            RequirementPrefixes = @('S13P3', 'S13P4', 'S13P4P1', 'S13P4P2', 'S13P4P2P1', 'S13P4P2P2')
            RequirementIds     = @()
        },
        [pscustomobject]@{
            Slug               = '9000-02-stream-state'
            Summary            = 'Stream-state requirements remain blocked without connection-scoped stream abstractions and receive/send state machines.'
            RequirementPrefixes = @('S3', 'S3P1', 'S3P2', 'S3P3', 'S3P4', 'S3P5')
            RequirementIds     = @()
        },
        [pscustomobject]@{
            Slug               = '9000-03-flow-control'
            Summary            = 'Flow-control behavior remains blocked without stream-state and connection credit accounting.'
            RequirementPrefixes = @('S4', 'S4P1', 'S4P2', 'S4P4', 'S4P5', 'S4P6')
            RequirementIds     = @()
        },
        [pscustomobject]@{
            Slug               = '9000-11-migration-core'
            Summary            = 'Connection-migration orchestration and path-selection requirements remain blocked without a connection-state machine.'
            RequirementPrefixes = @('S9', 'S9P1', 'S9P2', 'S9P3', 'S9P3P1', 'S9P3P2', 'S9P3P3')
            RequirementIds     = @()
        },
        [pscustomobject]@{
            Slug               = '9000-13-idle-and-close'
            Summary            = 'Close and draining lifecycle requirements remain blocked without connection close orchestration.'
            RequirementPrefixes = @('S10', 'S10P2', 'S10P2P1', 'S10P2P2', 'S10P2P3')
            RequirementIds     = @()
        },
        [pscustomobject]@{
            Slug               = '9000-14-stateless-reset'
            Summary            = 'Stateful stateless-reset acceptance and lifecycle requirements remain blocked without connection orchestration.'
            RequirementPrefixes = @('S10P3', 'S10P3P1', 'S10P3P2', 'S10P3P3')
            RequirementIds     = @()
        },
        [pscustomobject]@{
            Slug               = '9001-02-security-and-registry'
            Summary            = 'RFC 9001 stateful handshake, key-update, and security clauses remain blocked without TLS orchestration.'
            RequirementPrefixes = @('S6', 'S7', 'S8', 'S9', 'S10', 'SB', 'SBP1P1', 'SBP1P2', 'SBP2')
            RequirementIds     = @()
        },
        [pscustomobject]@{
            Slug               = '9002-06-key-discard-lifecycle'
            Summary            = 'RFC 9002 0-RTT rejection and secret-discard timing clauses remain blocked without TLS handshake orchestration and key-lifecycle state.'
            RequirementPrefixes = @()
            RequirementIds     = @(
                'REQ-QUIC-RFC9002-S6P4-0003',
                'REQ-QUIC-RFC9002-S6P4-0004'
            )
        }
    ) | Where-Object { $gapContent.Contains($_.Slug) }
}

function Get-MatchingGapEntries {
    param(
        [string]$RequirementId,
        [string]$SectionPrefix,
        $GapMappings
    )

    return @(
        foreach ($gap in $GapMappings)
        {
            $hasPrefixMatch = @($gap.RequirementPrefixes).Count -gt 0 -and $gap.RequirementPrefixes -contains $SectionPrefix
            $hasRequirementMatch = @($gap.RequirementIds).Count -gt 0 -and $gap.RequirementIds -contains $RequirementId
            if ($hasPrefixMatch -or $hasRequirementMatch)
            {
                $gap
            }
        }
    )
}

function New-EvidenceRecord {
    param(
        [string]$RequirementId,
        [string]$Source,
        $MethodRecord,
        [string]$Xref = ""
    )

    return [pscustomobject]@{
        requirement_id             = $RequirementId
        source                     = $Source
        x_test_ref                 = $Xref
        file                       = $MethodRecord.RepoPath
        class                      = $MethodRecord.ClassName
        member                     = $MethodRecord.FullyQualifiedMember
        method                     = $MethodRecord.MethodName
        line                       = $MethodRecord.LineNumber
        kinds                      = $MethodRecord.EvidenceKinds
        categories                 = $MethodRecord.Categories
        strength                   = $MethodRecord.EvidenceStrength
        associated_requirement_ids = $MethodRecord.RequirementIds
        requirement_tagged         = ($MethodRecord.RequirementIds -contains $RequirementId)
        class_level_only           = $MethodRecord.IsClassLevelOnly
    }
}

function Get-RequirementState {
    param(
        $Requirement,
        $Evidence,
        [bool]$HasSpecXrefs,
        [bool]$HasUnresolvedXrefs,
        $GapEntries
    )

    $requiredKinds = @(
        foreach ($name in 'positive', 'negative', 'edge', 'fuzz')
        {
            $value = $Requirement.coverage.$name
            if ($value -eq 'required')
            {
                $name
            }
        }
    )

    $focusedEvidence = @($Evidence | Where-Object { $_.strength -eq 'focused' })
    $broadEvidence = @($Evidence | Where-Object { $_.strength -eq 'broad' })
    $focusedKinds = @($focusedEvidence | ForEach-Object { $_.kinds } | Select-Object -Unique)
    $allKinds = @($Evidence | ForEach-Object { $_.kinds } | Select-Object -Unique)
    $missingRequiredKinds = @(
        foreach ($requiredKind in $requiredKinds)
        {
            if ($focusedKinds -notcontains $requiredKind)
            {
                $requiredKind
            }
        }
    )

    if (@($Evidence).Count -eq 0)
    {
        if (@($GapEntries).Count -gt 0)
        {
            return @{
                state = 'uncovered_blocked'
                missing_required_kinds = $requiredKinds
                work_queue_tags = @('blocked', 'new_tests_needed')
                primary_issue = 'missing_proof'
                rationale = 'No credible source-level proof path was found, and the requirement family is called out as blocked in REQUIREMENT-GAPS.md.'
            }
        }

        return @{
            state = 'uncovered_unblocked'
            missing_required_kinds = $requiredKinds
            work_queue_tags = @('new_tests_needed')
            primary_issue = 'missing_proof'
            rationale = 'No credible source-level proof path was found for this requirement.'
        }
    }

    if (@($focusedEvidence).Count -eq 0)
    {
        $tags = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        [void]$tags.Add('restructure_needed')
        if (@($requiredKinds).Count -gt 0 -and @($missingRequiredKinds).Count -gt 0)
        {
            [void]$tags.Add('new_tests_needed')
        }

        return @{
            state = 'covered_but_proof_too_broad'
            missing_required_kinds = $missingRequiredKinds
            work_queue_tags = @($tags | Sort-Object)
            primary_issue = 'test_structure'
            rationale = 'Evidence exists, but every proof path is broad or class-level, so the requirement still needs narrower proof slices.'
        }
    }

    if (@($missingRequiredKinds).Count -gt 0)
    {
        $tags = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        [void]$tags.Add('new_tests_needed')
        if (@($broadEvidence).Count -gt 0)
        {
            [void]$tags.Add('restructure_needed')
        }

        return @{
            state = 'partially_covered'
            missing_required_kinds = $missingRequiredKinds
            work_queue_tags = @($tags | Sort-Object)
            primary_issue = 'missing_proof'
            rationale = 'Some focused proof exists, but one or more required proof dimensions are still missing.'
        }
    }

    if (-not $HasSpecXrefs -or $HasUnresolvedXrefs)
    {
        return @{
            state = 'covered_but_missing_xrefs'
            missing_required_kinds = @()
            work_queue_tags = @('metadata_only')
            primary_issue = 'spec_metadata'
            rationale = 'Focused proof exists in source, but the canonical spec x_test_refs are missing or no longer resolve cleanly.'
        }
    }

    return @{
        state = 'trace_clean'
        missing_required_kinds = @()
        work_queue_tags = @('clean')
        primary_issue = 'none'
        rationale = 'Focused proof exists for the required coverage dimensions, and the canonical spec x_test_refs resolve to source evidence.'
    }
}

$testsRoot = Join-Path $RepoRoot 'tests\Incursa.Quic.Tests'
$specRoot = Join-Path $RepoRoot 'specs\requirements\quic'
$gapPath = Join-Path $specRoot 'REQUIREMENT-GAPS.md'

$specFiles = Get-ChildItem -Path $specRoot -Filter 'SPEC-QUIC-RFC*.json' -File | Sort-Object Name
$methodRecords = @(Get-TestMethodRecords -TestsRoot $testsRoot)
$gapMappings = @(Get-RequirementGapMappings -GapPath $gapPath)

$methodIndex = @{}
foreach ($method in $methodRecords)
{
    $key = "$($method.RepoPath)::$($method.MethodName)"
    $methodIndex[$key] = $method
}

$requirementEvidenceMap = @{}
foreach ($method in $methodRecords)
{
    foreach ($requirementId in $method.RequirementIds)
    {
        if (-not $requirementEvidenceMap.ContainsKey($requirementId))
        {
            $requirementEvidenceMap[$requirementId] = [System.Collections.Generic.List[object]]::new()
        }

        $requirementEvidenceMap[$requirementId].Add((New-EvidenceRecord -RequirementId $requirementId -Source 'requirement_attribute' -MethodRecord $method))
    }
}

$reportRequirements = [System.Collections.Generic.List[object]]::new()

foreach ($specFile in $specFiles)
{
    $spec = Get-Content $specFile.FullName -Raw | ConvertFrom-Json -Depth 100

    foreach ($requirement in $spec.requirements)
    {
        $requirementId = $requirement.id
        $sectionPrefix = Get-RequirementSectionPrefix -RequirementId $requirementId
        $specXrefs = if ($requirement.trace.PSObject.Properties.Name -contains 'x_test_refs') { @($requirement.trace.x_test_refs) } else { @() }
        $evidenceList = [System.Collections.Generic.List[object]]::new()

        if ($requirementEvidenceMap.ContainsKey($requirementId))
        {
            foreach ($evidence in $requirementEvidenceMap[$requirementId])
            {
                $evidenceList.Add($evidence)
            }
        }

        $resolvedXrefs = [System.Collections.Generic.List[object]]::new()
        $unresolvedXrefs = [System.Collections.Generic.List[object]]::new()

        foreach ($xref in $specXrefs)
        {
            $relativeRef = $xref.Split('::')[0].Replace('\', '/')
            $methodName = if ($xref -match '::(?<member>[A-Za-z_][A-Za-z0-9_]*)$') { $Matches.member } else { '' }
            $key = "$relativeRef::$methodName"

            if ($methodIndex.ContainsKey($key))
            {
                $methodRecord = $methodIndex[$key]
                $resolved = New-EvidenceRecord -RequirementId $requirementId -Source 'spec_xref' -MethodRecord $methodRecord -Xref $xref
                $resolvedXrefs.Add($resolved)

                $duplicate = $false
                foreach ($existing in $evidenceList)
                {
                    if ($existing.file -eq $resolved.file -and $existing.member -eq $resolved.member -and $existing.source -eq $resolved.source)
                    {
                        $duplicate = $true
                        break
                    }
                }

                if (-not $duplicate)
                {
                    $evidenceList.Add($resolved)
                }
            }
            else
            {
                $unresolvedXrefs.Add([pscustomobject]@{
                        requirement_id = $requirementId
                        x_test_ref     = $xref
                    })
            }
        }

        $evidence = @($evidenceList | Sort-Object file, member, source -Unique)
        $gapEntries = @(Get-MatchingGapEntries -RequirementId $requirement.id -SectionPrefix $sectionPrefix -GapMappings $gapMappings)
        $classification = Get-RequirementState -Requirement $requirement -Evidence $evidence -HasSpecXrefs (@($specXrefs).Count -gt 0) -HasUnresolvedXrefs (@($unresolvedXrefs).Count -gt 0) -GapEntries $gapEntries

        $kindCounts = [ordered]@{
            positive = 0
            negative = 0
            edge     = 0
            fuzz     = 0
            benchmark = 0
            unspecified = 0
        }

        foreach ($evidenceItem in $evidence)
        {
            foreach ($kind in $evidenceItem.kinds)
            {
                if ($kindCounts.Contains($kind))
                {
                    $kindCounts[$kind]++
                }
            }
        }

        $reportRequirements.Add([pscustomobject]@{
                requirement_id         = $requirementId
                artifact_id            = $spec.artifact_id
                rfc                    = if ($requirementId -match '^REQ-QUIC-(RFC\d+)-') { $Matches[1] } else { $spec.artifact_id.Replace('SPEC-QUIC-', '') }
                section_prefix         = $sectionPrefix
                title                  = $requirement.title
                statement              = $requirement.statement
                coverage_expectations  = [ordered]@{
                    positive = $requirement.coverage.positive
                    negative = $requirement.coverage.negative
                    edge     = $requirement.coverage.edge
                    fuzz     = $requirement.coverage.fuzz
                }
                state                  = $classification.state
                primary_issue          = $classification.primary_issue
                work_queue_tags        = $classification.work_queue_tags
                rationale              = $classification.rationale
                spec_test_ref_count    = @($specXrefs).Count
                spec_test_refs         = $specXrefs
                unresolved_test_refs   = $unresolvedXrefs
                evidence_summary       = [ordered]@{
                    total                   = @($evidence).Count
                    focused                 = @($evidence | Where-Object { $_.strength -eq 'focused' }).Count
                    broad                   = @($evidence | Where-Object { $_.strength -eq 'broad' }).Count
                    by_kind                 = $kindCounts
                    missing_required_kinds  = $classification.missing_required_kinds
                }
                gap_blockers           = @(
                    foreach ($gap in $gapEntries)
                    {
                        [pscustomobject]@{
                            slug    = $gap.Slug
                            summary = $gap.Summary
                        }
                    }
                )
                evidence               = $evidence
            })
    }
}

$requirementsArray = @($reportRequirements | Sort-Object requirement_id)
$stateGroups = $requirementsArray | Group-Object state | Sort-Object Name
$queueGroups = $requirementsArray | ForEach-Object { $_.work_queue_tags } | Group-Object | Sort-Object Name
$rfcSummaries = @(
    foreach ($group in ($requirementsArray | Group-Object rfc | Sort-Object Name))
    {
        $stateSummary = [ordered]@{}
        foreach ($stateGroup in ($group.Group | Group-Object state | Sort-Object Name))
        {
            $stateSummary[$stateGroup.Name] = $stateGroup.Count
        }

        [pscustomobject]@{
            rfc      = $group.Name
            total    = $group.Count
            by_state = $stateSummary
        }
    }
)

$summary = [ordered]@{
    generated_at          = (Get-Date).ToString('o')
    total_requirements    = $requirementsArray.Count
    by_state              = [ordered]@{}
    by_work_queue_tag     = [ordered]@{}
    by_rfc                = $rfcSummaries
}

foreach ($stateGroup in $stateGroups)
{
    $summary.by_state[$stateGroup.Name] = $stateGroup.Count
}

foreach ($queueGroup in $queueGroups)
{
    $summary.by_work_queue_tag[$queueGroup.Name] = $queueGroup.Count
}

$report = [ordered]@{
    generated_at = (Get-Date).ToString('o')
    repo_root    = $RepoRoot
    sources      = [ordered]@{
        spec_files         = @($specFiles | ForEach-Object { Get-RelativeRepoPath -Path $_.FullName })
        requirement_gaps   = Get-RelativeRepoPath -Path $gapPath
        tests_root         = Get-RelativeRepoPath -Path $testsRoot
        classification_notes = @(
            'RequirementHomes scaffolds are not counted as proof because they contain no executable test methods.',
            'Trait(\"Category\", ...) is treated as the current evidence tag source because CoverageType is not yet widely adopted in real tests.',
            'Requirement-owned homes with executable methods are treated as focused proof when they own exactly one requirement; methods with more than six associated requirements and the broad transport/frame codec aggregation tests are still treated as broad proof.'
        )
    }
    summary      = $summary
    requirements = $requirementsArray
}

$jsonDirectory = Split-Path -Parent $OutputJsonPath
$markdownDirectory = Split-Path -Parent $OutputMarkdownPath

if (-not (Test-Path $jsonDirectory))
{
    New-Item -Path $jsonDirectory -ItemType Directory | Out-Null
}

if (-not (Test-Path $markdownDirectory))
{
    New-Item -Path $markdownDirectory -ItemType Directory | Out-Null
}

$report | ConvertTo-Json -Depth 100 | Set-Content -Path $OutputJsonPath -NoNewline

$metadataExamples = @($requirementsArray | Where-Object { $_.work_queue_tags -contains 'metadata_only' } | Select-Object -First 12 -ExpandProperty requirement_id)
$restructureExamples = @($requirementsArray | Where-Object { $_.work_queue_tags -contains 'restructure_needed' } | Select-Object -First 12 -ExpandProperty requirement_id)
$newTestExamples = @($requirementsArray | Where-Object { $_.work_queue_tags -contains 'new_tests_needed' -and $_.state -ne 'uncovered_blocked' } | Select-Object -First 12 -ExpandProperty requirement_id)
$blockedExamples = @($requirementsArray | Where-Object { $_.state -eq 'uncovered_blocked' } | Select-Object -First 12 -ExpandProperty requirement_id)
$blockedQueueCount = if ($summary.by_work_queue_tag.Contains('blocked')) { $summary.by_work_queue_tag['blocked'] } else { 0 }

$markdown = [System.Text.StringBuilder]::new()
[void]$markdown.AppendLine('# QUIC Requirement Coverage Triage')
[void]$markdown.AppendLine()
[void]$markdown.AppendLine('## Sources')
[void]$markdown.AppendLine()
[void]$markdown.AppendLine('- Canonical specs: `specs/requirements/quic/SPEC-QUIC-RFC8999.json`, `SPEC-QUIC-RFC9000.json`, `SPEC-QUIC-RFC9001.json`, `SPEC-QUIC-RFC9002.json`.')
[void]$markdown.AppendLine('- Deferral and blocker ledger: `specs/requirements/quic/REQUIREMENT-GAPS.md`.')
[void]$markdown.AppendLine('- Test evidence: executable methods under `tests/Incursa.Quic.Tests`, including requirement-owned homes; empty scaffolds still contribute no evidence.')
[void]$markdown.AppendLine('- Evidence tags: `RequirementAttribute`, `Trait("Category", ...)`, and any canonical `trace.x_test_refs` that still resolve to source.')
[void]$markdown.AppendLine()
[void]$markdown.AppendLine('## Summary')
[void]$markdown.AppendLine()
[void]$markdown.AppendLine("| State | Count |")
[void]$markdown.AppendLine('| --- | ---: |')
foreach ($state in 'trace_clean', 'covered_but_missing_xrefs', 'covered_but_proof_too_broad', 'partially_covered', 'uncovered_blocked', 'uncovered_unblocked')
{
    $count = if ($summary.by_state.Contains($state)) { $summary.by_state[$state] } else { 0 }
    [void]$markdown.AppendLine("| $state | $count |")
}

[void]$markdown.AppendLine()
[void]$markdown.AppendLine("| Work queue tag | Count |")
[void]$markdown.AppendLine('| --- | ---: |')
foreach ($tag in 'clean', 'metadata_only', 'restructure_needed', 'new_tests_needed', 'blocked')
{
    $count = if ($summary.by_work_queue_tag.Contains($tag)) { $summary.by_work_queue_tag[$tag] } else { 0 }
    [void]$markdown.AppendLine("| $tag | $count |")
}

[void]$markdown.AppendLine()
[void]$markdown.AppendLine('## Queue')
[void]$markdown.AppendLine()
[void]$markdown.AppendLine("- Metadata-only fixes: $($summary.by_work_queue_tag['metadata_only']) requirements. Examples: $([string]::Join(', ', $metadataExamples)).")
[void]$markdown.AppendLine("- Restructure-needed proof: $($summary.by_work_queue_tag['restructure_needed']) requirements. Examples: $([string]::Join(', ', $restructureExamples)).")
[void]$markdown.AppendLine("- New proof or implementation work: $($summary.by_work_queue_tag['new_tests_needed']) requirements. Examples: $([string]::Join(', ', $newTestExamples)).")
[void]$markdown.AppendLine("- Blocked by recorded gap families: $blockedQueueCount requirements. Examples: $([string]::Join(', ', $blockedExamples)).")
[void]$markdown.AppendLine()
[void]$markdown.AppendLine('## RFC Breakdown')
[void]$markdown.AppendLine()
[void]$markdown.AppendLine('| RFC | Total | trace_clean | missing_xrefs | proof_too_broad | partially_covered | uncovered_blocked | uncovered_unblocked |')
[void]$markdown.AppendLine('| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |')
foreach ($rfcSummary in $rfcSummaries)
{
    $byState = $rfcSummary.by_state
    $traceClean = if ($byState.Contains('trace_clean')) { $byState['trace_clean'] } else { 0 }
    $missingXrefs = if ($byState.Contains('covered_but_missing_xrefs')) { $byState['covered_but_missing_xrefs'] } else { 0 }
    $proofTooBroad = if ($byState.Contains('covered_but_proof_too_broad')) { $byState['covered_but_proof_too_broad'] } else { 0 }
    $partial = if ($byState.Contains('partially_covered')) { $byState['partially_covered'] } else { 0 }
    $blocked = if ($byState.Contains('uncovered_blocked')) { $byState['uncovered_blocked'] } else { 0 }
    $unblocked = if ($byState.Contains('uncovered_unblocked')) { $byState['uncovered_unblocked'] } else { 0 }
    [void]$markdown.AppendLine("| $($rfcSummary.rfc) | $($rfcSummary.total) | $traceClean | $missingXrefs | $proofTooBroad | $partial | $blocked | $unblocked |")
}

$markdown.ToString() | Set-Content -Path $OutputMarkdownPath -NoNewline

Write-Host "Wrote $OutputJsonPath"
Write-Host "Wrote $OutputMarkdownPath"
