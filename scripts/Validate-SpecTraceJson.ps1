[CmdletBinding()]
param(
    [string]$RepoRoot = (Join-Path $PSScriptRoot '..'),
    [string[]]$Profiles = @('core'),
    [string]$SchemaUri = 'https://github.com/incursa/spec-trace/raw/refs/heads/main/model/model.schema.json',
    [string]$JsonReportPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'spec-trace\SpecTraceMigration.Common.ps1')

function Add-ValidationError {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[string]]$Errors,

        [Parameter(Mandatory)]
        [string]$Message
    )

    $Errors.Add($Message)
}

function Get-ExpectedArtifactTypeFromRelativePath {
    param([string]$RelativePath)

    if ($RelativePath.StartsWith('specs/requirements/', [System.StringComparison]::OrdinalIgnoreCase)) { return 'specification' }
    if ($RelativePath.StartsWith('specs/architecture/', [System.StringComparison]::OrdinalIgnoreCase)) { return 'architecture' }
    if ($RelativePath.StartsWith('specs/work-items/', [System.StringComparison]::OrdinalIgnoreCase)) { return 'work_item' }
    if ($RelativePath.StartsWith('specs/verification/', [System.StringComparison]::OrdinalIgnoreCase)) { return 'verification' }
    return $null
}

function Get-ExpectedDomainFromRelativePath {
    param([string]$RelativePath)

    $parts = $RelativePath -split '/'
    if ($parts.Count -lt 3) {
        return $null
    }

    return $parts[2]
}

function Normalize-Profiles {
    param([string[]]$Profiles)

    $normalized = New-Object System.Collections.Generic.List[string]
    foreach ($profile in @($Profiles)) {
        foreach ($value in ($profile -split ',')) {
            $trimmed = $value.Trim().ToLowerInvariant()
            if ($trimmed.Length -gt 0 -and -not $normalized.Contains($trimmed)) {
                $normalized.Add($trimmed)
            }
        }
    }

    if ($normalized.Count -eq 0) {
        $normalized.Add('core')
    }

    return @($normalized)
}

function Get-NonEmptyArray {
    param([object]$Value)

    $values = New-Object System.Collections.Generic.List[object]
    foreach ($item in @($Value)) {
        if ($item -is [System.Collections.IEnumerable] -and -not ($item -is [string]) -and -not ($item -is [System.Collections.IDictionary])) {
            foreach ($nestedItem in @($item)) {
                if ($null -ne $nestedItem -and -not [string]::IsNullOrWhiteSpace($nestedItem.ToString())) {
                    $values.Add($nestedItem)
                }
            }

            continue
        }

        if ($null -ne $item -and -not [string]::IsNullOrWhiteSpace($item.ToString())) {
            $values.Add($item)
        }
    }

    return $values.ToArray()
}

function Get-SpecTraceJsonSchemaText {
    param(
        [Parameter(Mandatory)]
        [string]$SchemaUri
    )

    try {
        $response = Invoke-WebRequest -Uri $SchemaUri -MaximumRedirection 5 -ErrorAction Stop
    }
    catch {
        throw "Could not download SpecTrace JSON schema from '$SchemaUri': $($_.Exception.Message)"
    }

    if ([string]::IsNullOrWhiteSpace($response.Content)) {
        throw "Downloaded empty SpecTrace JSON schema content from '$SchemaUri'."
    }

    return $response.Content
}

function Test-ReferenceExists {
    param(
        [Parameter(Mandatory)]
        [string]$Value,

        [Parameter(Mandatory)]
        [hashtable]$ArtifactById,

        [Parameter(Mandatory)]
        [hashtable]$RequirementById
    )

    if ($Value -match '^REQ-[A-Z0-9-]+$') {
        return $RequirementById.Contains($Value)
    }

    if ($Value -match '^(SPEC|ARC|WI|VER)-[A-Z0-9-]+$') {
        return $ArtifactById.Contains($Value)
    }

    return $true
}

$resolvedRepoRoot = Get-SpecTraceMigrationRepoRoot -RootPath $RepoRoot
$schemaText = Get-SpecTraceJsonSchemaText -SchemaUri $SchemaUri

$profiles = Normalize-Profiles -Profiles $Profiles
$jsonPaths = @(Get-SpecTraceCanonicalJsonArtifactPaths -RepoRoot $resolvedRepoRoot)
if ($jsonPaths.Count -eq 0) {
    throw "No canonical SpecTrace JSON artifacts were found under '$resolvedRepoRoot'."
}

$errors = New-Object System.Collections.Generic.List[string]
$artifactById = @{}
$requirementById = @{}
$artifactRecords = New-Object System.Collections.Generic.List[object]

foreach ($jsonPath in $jsonPaths) {
    $relativePath = Get-RepoRelativePath -RepoRoot $resolvedRepoRoot -Path $jsonPath
    $jsonText = Get-Content -LiteralPath $jsonPath -Raw

    try {
        $null = Test-Json -Json $jsonText -Schema $schemaText -ErrorAction Stop
    }
    catch {
        Add-ValidationError -Errors $errors -Message "Schema validation failed for '$relativePath': $($_.Exception.Message)"
        continue
    }

    $artifact = $jsonText | ConvertFrom-Json -AsHashtable -Depth 100
    $expectedArtifactType = Get-ExpectedArtifactTypeFromRelativePath -RelativePath $relativePath
    $expectedDomain = Get-ExpectedDomainFromRelativePath -RelativePath $relativePath
    $expectedFileStem = [System.IO.Path]::GetFileNameWithoutExtension($jsonPath)
    $markdownCompanion = [System.IO.Path]::ChangeExtension($jsonPath, '.md')

    if ($artifact['artifact_id'] -ne $expectedFileStem) {
        Add-ValidationError -Errors $errors -Message "Artifact id/file mismatch in '$relativePath': expected '$expectedFileStem' but found '$($artifact['artifact_id'])'."
    }
    if ($artifact['artifact_type'] -ne $expectedArtifactType) {
        Add-ValidationError -Errors $errors -Message "Artifact type/path mismatch in '$relativePath': expected '$expectedArtifactType' but found '$($artifact['artifact_type'])'."
    }
    if ($artifact['domain'] -ne $expectedDomain) {
        Add-ValidationError -Errors $errors -Message "Domain/path mismatch in '$relativePath': expected '$expectedDomain' but found '$($artifact['domain'])'."
    }
    if (Test-Path -LiteralPath $markdownCompanion) {
        $markdownRelativePath = Get-RepoRelativePath -RepoRoot $resolvedRepoRoot -Path $markdownCompanion
        Add-ValidationError -Errors $errors -Message "Residual canonical Markdown artifact '$markdownRelativePath' exists for '$relativePath'. Remove the sibling '.md' file."
    }

    $artifactId = $artifact['artifact_id']
    if ($artifactById.Contains($artifactId)) {
        Add-ValidationError -Errors $errors -Message "Duplicate artifact id '$artifactId' in '$relativePath' and '$($artifactById[$artifactId].path)'."
        continue
    }

    $record = [ordered]@{
        id       = $artifactId
        type     = $artifact['artifact_type']
        path     = $relativePath
        artifact = $artifact
    }
    $artifactById[$artifactId] = $record
    $artifactRecords.Add($record)

    if ($artifact['artifact_type'] -eq 'specification') {
        foreach ($requirement in @($artifact['requirements'])) {
            $requirementId = $requirement['id']
            if ($requirementById.Contains($requirementId)) {
                Add-ValidationError -Errors $errors -Message "Duplicate requirement id '$requirementId' in '$relativePath' and '$($requirementById[$requirementId].path)'."
                continue
            }

            $requirementById[$requirementId] = [ordered]@{
                id          = $requirementId
                path        = $relativePath
                artifact_id = $artifactId
                requirement = $requirement
            }
        }
    }
}

$downstreamRefs = @{
    architecture = New-Object System.Collections.Generic.HashSet[string] ([System.StringComparer]::Ordinal)
    work_item    = New-Object System.Collections.Generic.HashSet[string] ([System.StringComparer]::Ordinal)
    verification = New-Object System.Collections.Generic.HashSet[string] ([System.StringComparer]::Ordinal)
}

foreach ($record in $artifactRecords) {
    $artifact = $record.artifact
    $relativePath = $record.path

    foreach ($relatedArtifact in (Get-NonEmptyArray -Value $artifact['related_artifacts'])) {
        if (-not (Test-ReferenceExists -Value $relatedArtifact -ArtifactById $artifactById -RequirementById $requirementById)) {
            Add-ValidationError -Errors $errors -Message "Unresolved related artifact '$relatedArtifact' in '$relativePath'."
        }
    }

    switch ($artifact['artifact_type']) {
        'architecture' {
            foreach ($requirementId in (Get-NonEmptyArray -Value $artifact['satisfies'])) {
                if (-not $requirementById.Contains($requirementId)) {
                    Add-ValidationError -Errors $errors -Message "Unresolved requirement '$requirementId' in satisfies for '$relativePath'."
                }
            }
        }
        'work_item' {
            foreach ($requirementId in (Get-NonEmptyArray -Value $artifact['addresses'])) {
                if (-not $requirementById.Contains($requirementId)) {
                    Add-ValidationError -Errors $errors -Message "Unresolved requirement '$requirementId' in addresses for '$relativePath'."
                }
            }
            foreach ($architectureId in (Get-NonEmptyArray -Value $artifact['design_links'])) {
                if (-not ($artifactById.Contains($architectureId) -and $artifactById[$architectureId].type -eq 'architecture')) {
                    Add-ValidationError -Errors $errors -Message "Unresolved architecture '$architectureId' in design_links for '$relativePath'."
                }
            }
            foreach ($verificationId in (Get-NonEmptyArray -Value $artifact['verification_links'])) {
                if (-not ($artifactById.Contains($verificationId) -and $artifactById[$verificationId].type -eq 'verification')) {
                    Add-ValidationError -Errors $errors -Message "Unresolved verification '$verificationId' in verification_links for '$relativePath'."
                }
            }
        }
        'verification' {
            foreach ($requirementId in (Get-NonEmptyArray -Value $artifact['verifies'])) {
                if (-not $requirementById.Contains($requirementId)) {
                    Add-ValidationError -Errors $errors -Message "Unresolved requirement '$requirementId' in verifies for '$relativePath'."
                }
            }
        }
        'specification' {
            foreach ($requirement in @($artifact['requirements'])) {
                $trace = if ($requirement.Contains('trace')) { $requirement['trace'] } else { @{} }
                foreach ($traceKey in @('satisfied_by', 'implemented_by', 'verified_by', 'derived_from', 'supersedes', 'related')) {
                    foreach ($value in (Get-NonEmptyArray -Value $trace[$traceKey])) {
                        if (-not (Test-ReferenceExists -Value $value -ArtifactById $artifactById -RequirementById $requirementById)) {
                            Add-ValidationError -Errors $errors -Message "Unresolved '$traceKey' reference '$value' in '$relativePath' ($($requirement['id']))."
                        }
                    }
                }

                foreach ($architectureId in (Get-NonEmptyArray -Value $trace['satisfied_by'])) {
                    [void]$downstreamRefs['architecture'].Add($architectureId)
                    if ($artifactById.Contains($architectureId) -and @($artifactById[$architectureId].artifact['satisfies']) -notcontains $requirement['id']) {
                        Add-ValidationError -Errors $errors -Message "Missing reciprocal architecture trace from '$architectureId' back to '$($requirement['id'])'."
                    }
                }
                foreach ($workItemId in (Get-NonEmptyArray -Value $trace['implemented_by'])) {
                    [void]$downstreamRefs['work_item'].Add($workItemId)
                    if ($artifactById.Contains($workItemId) -and @($artifactById[$workItemId].artifact['addresses']) -notcontains $requirement['id']) {
                        Add-ValidationError -Errors $errors -Message "Missing reciprocal work-item trace from '$workItemId' back to '$($requirement['id'])'."
                    }
                }
                foreach ($verificationId in (Get-NonEmptyArray -Value $trace['verified_by'])) {
                    [void]$downstreamRefs['verification'].Add($verificationId)
                    if ($artifactById.Contains($verificationId) -and @($artifactById[$verificationId].artifact['verifies']) -notcontains $requirement['id']) {
                        Add-ValidationError -Errors $errors -Message "Missing reciprocal verification trace from '$verificationId' back to '$($requirement['id'])'."
                    }
                }
            }
        }
    }
}

if ($profiles -contains 'traceable' -or $profiles -contains 'auditable') {
    foreach ($requirementRecord in $requirementById.Values) {
        $trace = if ($requirementRecord.requirement.Contains('trace')) { $requirementRecord.requirement['trace'] } else { @{} }
        $downstreamCount = (Get-NonEmptyArray -Value $trace['satisfied_by']).Count + (Get-NonEmptyArray -Value $trace['implemented_by']).Count + (Get-NonEmptyArray -Value $trace['verified_by']).Count
        if ($downstreamCount -eq 0) {
            Add-ValidationError -Errors $errors -Message "Requirement '$($requirementRecord.id)' is missing downstream trace links."
        }
    }
}

if ($profiles -contains 'auditable') {
    foreach ($requirementRecord in $requirementById.Values) {
        $trace = if ($requirementRecord.requirement.Contains('trace')) { $requirementRecord.requirement['trace'] } else { @{} }
        if ((Get-NonEmptyArray -Value $trace['verified_by']).Count -eq 0) {
            Add-ValidationError -Errors $errors -Message "Requirement '$($requirementRecord.id)' is missing verification coverage."
        }
    }

    foreach ($record in $artifactRecords | Where-Object { $_.type -eq 'verification' }) {
        if ((Get-NonEmptyArray -Value $record.artifact['evidence']).Count -eq 0) {
            Add-ValidationError -Errors $errors -Message "Verification artifact '$($record.id)' is missing evidence entries."
        }
    }

    foreach ($record in $artifactRecords | Where-Object { $_.type -in @('architecture', 'work_item', 'verification') }) {
        if (-not $downstreamRefs[$record.type].Contains($record.id)) {
            Add-ValidationError -Errors $errors -Message "Orphan $($record.type) artifact '$($record.id)' is not targeted by any requirement trace."
        }
    }
}

$report = [ordered]@{
    repo_root      = $resolvedRepoRoot
    schema_uri     = $SchemaUri
    profiles       = $profiles
    artifact_count = $jsonPaths.Count
    errors         = @($errors)
}

if (-not [string]::IsNullOrWhiteSpace($JsonReportPath)) {
    $resolvedReportPath = if ([System.IO.Path]::IsPathRooted($JsonReportPath)) { $JsonReportPath } else { Join-Path $resolvedRepoRoot $JsonReportPath }
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $resolvedReportPath) | Out-Null
    $report | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $resolvedReportPath
}

if ($errors.Count -gt 0) {
    throw "SpecTrace JSON validation failed with $($errors.Count) error(s).`n$($errors -join [Environment]::NewLine)"
}

Write-Output "Validated $($jsonPaths.Count) SpecTrace JSON artifact(s) for profile(s): $($profiles -join ', ')."
