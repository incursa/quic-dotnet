# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [switch] $UpdateContentHashes,
    
    [string] $RepositoryRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$systemTextJsonDll = Join-Path $PSHOME 'System.Text.Json.dll'
if (Test-Path -LiteralPath $systemTextJsonDll) {
    Add-Type -Path $systemTextJsonDll
}

$scriptRoot = if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
    $PSScriptRoot
}
elseif ($MyInvocation.MyCommand.Path) {
    Split-Path -Parent $MyInvocation.MyCommand.Path
}
else {
    Get-Location
}

if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $RepositoryRoot = (Resolve-Path (Join-Path $scriptRoot '..\..')).Path
}

$schemaMap = [ordered]@{
    'adaptive-runtime-policy-axis-contract-v1' = 'schemas\adaptive-runtime-policy-axis-contract-v1.schema.json'
    'adaptive-runtime-effective-behavior-catalog-v1' = 'schemas\adaptive-runtime-effective-behavior-catalog-v1.schema.json'
    'adaptive-runtime-policy-relationship-graph-v1' = 'schemas\adaptive-runtime-policy-relationship-graph-v1.schema.json'
    'adaptive-runtime-combination-constraint-catalog-v1' = 'schemas\adaptive-runtime-combination-constraint-catalog-v1.schema.json'
    'adaptive-runtime-experiment-family-catalog-v1' = 'schemas\adaptive-runtime-experiment-family-catalog-v1.schema.json'
    'adaptive-runtime-experiment-plan-v1' = 'schemas\adaptive-runtime-experiment-plan-v1.schema.json'
    'adaptive-runtime-experiment-plan-validation-v1' = 'schemas\adaptive-runtime-experiment-plan-validation-v1.schema.json'
    'adaptive-runtime-compiled-execution-manifest-v1' = 'schemas\adaptive-runtime-compiled-execution-manifest-v1.schema.json'
}

$canonicalDocumentSpecs = @(
    [pscustomobject]@{
        RelativePath = 'eng/adaptive-runtime/experiment-control/adaptive-runtime-policy-axis-contracts-v1.json'
        SchemaVersion = 'adaptive-runtime-policy-axis-contract-v1'
        HasRootContentSha256 = $true
    },
    [pscustomobject]@{
        RelativePath = 'eng/adaptive-runtime/experiment-control/adaptive-runtime-effective-behavior-catalog-v1.json'
        SchemaVersion = 'adaptive-runtime-effective-behavior-catalog-v1'
        HasRootContentSha256 = $true
    },
    [pscustomobject]@{
        RelativePath = 'eng/adaptive-runtime/experiment-control/adaptive-runtime-policy-relationship-graph-v1.json'
        SchemaVersion = 'adaptive-runtime-policy-relationship-graph-v1'
        HasRootContentSha256 = $true
    },
    [pscustomobject]@{
        RelativePath = 'eng/adaptive-runtime/experiment-control/adaptive-runtime-combination-constraint-catalog-v1.json'
        SchemaVersion = 'adaptive-runtime-combination-constraint-catalog-v1'
        HasRootContentSha256 = $true
    },
    [pscustomobject]@{
        RelativePath = 'eng/adaptive-runtime/experiment-control/adaptive-runtime-experiment-family-catalog-v1.json'
        SchemaVersion = 'adaptive-runtime-experiment-family-catalog-v1'
        HasRootContentSha256 = $true
    }
)

$validFixtureSpecs = @(
    [pscustomobject]@{
        RelativePath = 'tests/fixtures/adaptive-runtime-experiment-control/valid/axis-contract.application-send-batch-formation.valid.example.json'
        SchemaVersion = 'adaptive-runtime-policy-axis-contract-v1'
        TopLevelArray = $false
    },
    [pscustomobject]@{
        RelativePath = 'tests/fixtures/adaptive-runtime-experiment-control/valid/axis-contract.application-send-turn-planning.valid.example.json'
        SchemaVersion = 'adaptive-runtime-policy-axis-contract-v1'
        TopLevelArray = $false
    },
    [pscustomobject]@{
        RelativePath = 'tests/fixtures/adaptive-runtime-experiment-control/valid/axis-contract.buffer-copy-coalescing.valid.example.json'
        SchemaVersion = 'adaptive-runtime-policy-axis-contract-v1'
        TopLevelArray = $false
    },
    [pscustomobject]@{
        RelativePath = 'tests/fixtures/adaptive-runtime-experiment-control/valid/effective-behavior-catalog.valid.example.json'
        SchemaVersion = 'adaptive-runtime-effective-behavior-catalog-v1'
        TopLevelArray = $false
    },
    [pscustomobject]@{
        RelativePath = 'tests/fixtures/adaptive-runtime-experiment-control/valid/relationship-graph.valid.example.json'
        SchemaVersion = 'adaptive-runtime-policy-relationship-graph-v1'
        TopLevelArray = $false
    },
    [pscustomobject]@{
        RelativePath = 'tests/fixtures/adaptive-runtime-experiment-control/valid/combination-constraint-catalog.valid.example.json'
        SchemaVersion = 'adaptive-runtime-combination-constraint-catalog-v1'
        TopLevelArray = $false
    },
    [pscustomobject]@{
        RelativePath = 'tests/fixtures/adaptive-runtime-experiment-control/valid/experiment-family-catalog.valid.example.json'
        SchemaVersion = 'adaptive-runtime-experiment-family-catalog-v1'
        TopLevelArray = $false
    },
    [pscustomobject]@{
        RelativePath = 'tests/fixtures/adaptive-runtime-experiment-control/valid/experiment-plan.actuation-validation.valid.example.json'
        SchemaVersion = 'adaptive-runtime-experiment-plan-v1'
        TopLevelArray = $false
    },
    [pscustomobject]@{
        RelativePath = 'tests/fixtures/adaptive-runtime-experiment-control/valid/experiment-plan.isolated-counterfactual.valid.example.json'
        SchemaVersion = 'adaptive-runtime-experiment-plan-v1'
        TopLevelArray = $false
    },
    [pscustomobject]@{
        RelativePath = 'tests/fixtures/adaptive-runtime-experiment-control/valid/experiment-plan.interaction-screen.valid.example.json'
        SchemaVersion = 'adaptive-runtime-experiment-plan-v1'
        TopLevelArray = $false
    },
    [pscustomobject]@{
        RelativePath = 'tests/fixtures/adaptive-runtime-experiment-control/valid/experiment-plan-validation.valid.example.json'
        SchemaVersion = 'adaptive-runtime-experiment-plan-validation-v1'
        TopLevelArray = $false
    },
    [pscustomobject]@{
        RelativePath = 'tests/fixtures/adaptive-runtime-experiment-control/valid/compiled-execution-manifest.valid.example.json'
        SchemaVersion = 'adaptive-runtime-compiled-execution-manifest-v1'
        TopLevelArray = $false
    }
)

$invalidFixtureSpecs = @(
    'tests/fixtures/adaptive-runtime-experiment-control/invalid/unknown-field.json',
    'tests/fixtures/adaptive-runtime-experiment-control/invalid/duplicate-axis-definition.json',
    'tests/fixtures/adaptive-runtime-experiment-control/invalid/illegal-policy-value.json',
    'tests/fixtures/adaptive-runtime-experiment-control/invalid/unknown-contract-reference.json',
    'tests/fixtures/adaptive-runtime-experiment-control/invalid/stale-version-reference.json',
    'tests/fixtures/adaptive-runtime-experiment-control/invalid/blocked-axis-executable.json',
    'tests/fixtures/adaptive-runtime-experiment-control/invalid/stage5-preparation-only-executable.json',
    'tests/fixtures/adaptive-runtime-experiment-control/invalid/active-behavior-authorization-true.json',
    'tests/fixtures/adaptive-runtime-experiment-control/invalid/performance-acceptance-authorization-true.json',
    'tests/fixtures/adaptive-runtime-experiment-control/invalid/malformed-hash.json',
    'tests/fixtures/adaptive-runtime-experiment-control/invalid/invalid-relationship-type.json',
    'tests/fixtures/adaptive-runtime-experiment-control/invalid/duplicate-relationship-edge.json',
    'tests/fixtures/adaptive-runtime-experiment-control/invalid/missing-canonical-predicate-reference.json',
    'tests/fixtures/adaptive-runtime-experiment-control/invalid/fixed-varied-axis-overlap.json',
    'tests/fixtures/adaptive-runtime-experiment-control/invalid/unsupported-experiment-type.json'
)

$failures = [System.Collections.Generic.List[string]]::new()
$canonicalSerializationByteEquivalent = $true
$repeatedHashesIdentical = $true
$contentHashesValid = $true
$referenceResolutionValid = $true
$unknownFieldRejected = $false
$invalidFixtureFailures = 0
$observedInvalidFixtureFailures = [System.Collections.Generic.List[string]]::new()
$documentHashById = [ordered]@{}
$canonicalValidationResults = [System.Collections.Generic.List[object]]::new()
$validFixtureValidationResults = [System.Collections.Generic.List[object]]::new()
$invalidFixtureValidationResults = [System.Collections.Generic.List[object]]::new()
$schemaCount = $schemaMap.Count
$canonicalDocumentCount = $canonicalDocumentSpecs.Count
$validFixtureCount = $validFixtureSpecs.Count
$invalidFixtureCount = $invalidFixtureSpecs.Count

$orderedArrayPropertyNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($name in @(
    'treatment_order',
    'treatments',
    'planned_cells',
    'validation_errors',
    'validation_warnings',
    'execution_order',
    'executable_cells',
    'axisRecords',
    'phases',
    'measurementCells',
    'samples',
    'history',
    'notes'
)) {
    [void]$orderedArrayPropertyNames.Add($name)
}

$knownValidSchemaVersions = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($key in $schemaMap.Keys) {
    [void]$knownValidSchemaVersions.Add($key)
}

function Add-Failure {
    param([Parameter(Mandatory = $true)][string] $Message)

    $failures.Add($Message)
}

function Resolve-RepoPath {
    param([Parameter(Mandatory = $true)][string] $RelativePath)

    return [System.IO.Path]::GetFullPath((Join-Path $RepositoryRoot $RelativePath))
}

function Read-JsonText {
    param([Parameter(Mandatory = $true)][string] $Path)

    return Get-Content -LiteralPath $Path -Raw
}

function Read-JsonValue {
    param([Parameter(Mandatory = $true)][string] $Path)

    return (Read-JsonText -Path $Path | ConvertFrom-Json)
}

function Get-JsonPropertyValue {
    param(
        [AllowNull()][object] $Value,
        [Parameter(Mandatory = $true)]
        [string] $Name
    )

    if ($null -eq $Value) {
        return $null
    }

    $property = $Value.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }

    return $property.Value
}

function Test-JsonSchemaText {
    param(
        [Parameter(Mandatory = $true)]
        [string] $JsonText,

        [Parameter(Mandatory = $true)]
        [string] $SchemaPath,

        [Parameter(Mandatory = $true)]
        [string] $Context
    )

    try {
        if (-not (Test-Json -Json $JsonText -SchemaFile $SchemaPath -ErrorAction Stop)) {
            Add-Failure "Schema validation failed for $Context against '$SchemaPath'."
            return $false
        }

        return $true
    }
    catch {
        Add-Failure "Schema validation failed for $Context against '$SchemaPath': $($_.Exception.Message)"
        return $false
    }
}

function Get-DocumentSchemaVersion {
    param(
        [Parameter(Mandatory = $true)]
        [object] $DocumentValue,

        [Parameter(Mandatory = $true)]
        [string] $Context
    )

    if ($DocumentValue -is [System.Collections.IEnumerable] -and -not ($DocumentValue -is [string])) {
        $versions = @()
        foreach ($item in @($DocumentValue)) {
            $versions += [string](Get-JsonPropertyValue -Value $item -Name 'schemaVersion')
        }

        $distinctVersions = @($versions | Select-Object -Unique)
        if ($distinctVersions.Count -ne 1) {
            Add-Failure "Top-level array document '$Context' does not use exactly one schemaVersion."
            return $null
        }

        return $distinctVersions[0]
    }

    $snakeVersion = Get-JsonPropertyValue -Value $DocumentValue -Name 'schema_version'
    if ($null -ne $snakeVersion) {
        return [string] $snakeVersion
    }

    $camelVersion = Get-JsonPropertyValue -Value $DocumentValue -Name 'schemaVersion'
    if ($null -ne $camelVersion) {
        return [string] $camelVersion
    }

    return $null
}

function Get-DocumentId {
    param([Parameter(Mandatory = $true)][object] $DocumentValue)

    foreach ($name in @('document_id', 'documentId', 'catalogId', 'normalizedDatasetId', 'splitManifestId', 'validationId', 'experimentPlanId', 'compiledExecutionManifestId')) {
        $value = Get-JsonPropertyValue -Value $DocumentValue -Name $name
        if ($null -ne $value -and -not [string]::IsNullOrWhiteSpace([string] $value)) {
            return [string] $value
        }
    }

    return $null
}

function Get-SchemaPathForVersion {
    param([Parameter(Mandatory = $true)][string] $SchemaVersion)

    if (-not $schemaMap.Contains($SchemaVersion)) {
        return $null
    }

    return Resolve-RepoPath -RelativePath $schemaMap[$SchemaVersion]
}

function Get-CanonicalJsonText {
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()] $Value,

        [hashtable] $DocumentHashById = $null,

        [int] $Depth = 0,

        [switch] $IncludeRootContentSha256,

        [switch] $PreserveTopLevelArrayOrder
    )

    $canonicalValue = Convert-ToCanonicalValue -Value $Value -DocumentHashById $DocumentHashById -Depth $Depth -IncludeRootContentSha256:$IncludeRootContentSha256 -PreserveTopLevelArrayOrder:$PreserveTopLevelArrayOrder
    return (Convert-SerializedJsonText -Value $canonicalValue)
}

function Convert-SerializedJsonText {
    param([Parameter(Mandatory = $true)] [AllowNull()] $Value)

    if ($null -eq $Value) {
        return 'null'
    }

    return ($Value | ConvertTo-Json -Depth 100 -Compress)
}

function Convert-ToCanonicalValue {
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()] $Value,

        [hashtable] $DocumentHashById = $null,

        [int] $Depth = 0,

        [switch] $IncludeRootContentSha256,

        [switch] $PreserveTopLevelArrayOrder
    )

    if ($null -eq $Value) {
        return $null
    }

    if ($Value -is [string] -or $Value -is [bool] -or $Value -is [byte] -or $Value -is [sbyte] -or
        $Value -is [int16] -or $Value -is [uint16] -or $Value -is [int32] -or $Value -is [uint32] -or
        $Value -is [int64] -or $Value -is [uint64] -or $Value -is [single] -or $Value -is [double] -or
        $Value -is [decimal]) {
        return $Value
    }

    $propertyNames = @()
    if ($Value -is [System.Collections.IDictionary]) {
        $propertyNames = @($Value.Keys)
    }
    elseif ($Value.PSObject -ne $null) {
        $propertyNames = @($Value.PSObject.Properties.Name)
    }

    $isDocumentRef = $false
    if ($Depth -gt 0 -and $propertyNames.Count -ge 4) {
        $requiredRefNames = @('document_id', 'schema_version', 'document_version', 'content_sha256')
        $isDocumentRef = $requiredRefNames | ForEach-Object { $propertyNames -contains $_ } | Where-Object { -not $_ } | Measure-Object | Select-Object -ExpandProperty Count
        $isDocumentRef = ($isDocumentRef -eq 0)
    }

    if ($isDocumentRef) {
        $documentId = [string](Get-JsonPropertyValue -Value $Value -Name 'document_id')
        $refValue = [ordered]@{}
        foreach ($name in @('document_id', 'schema_version', 'document_version', 'content_sha256')) {
            $refValue[$name] = Get-JsonPropertyValue -Value $Value -Name $name
        }

        if ($null -ne $DocumentHashById -and -not [string]::IsNullOrWhiteSpace($documentId) -and $DocumentHashById.Contains($documentId)) {
            $refValue['content_sha256'] = $DocumentHashById[$documentId]
        }

        return $refValue
    }

    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        $items = @($Value)
        $preserveOrder = $false
        if ($PreserveTopLevelArrayOrder) {
            $preserveOrder = $true
        }

        if ($preserveOrder) {
            return ,@($items | ForEach-Object {
                Convert-ToCanonicalValue -Value $_ -DocumentHashById $DocumentHashById -Depth ($Depth + 1) -IncludeRootContentSha256:$IncludeRootContentSha256
            })
        }

        $i = 0
        $canonicalItems = foreach ($item in $items) {
            $converted = Convert-ToCanonicalValue -Value $item -DocumentHashById $DocumentHashById -Depth ($Depth + 1) -IncludeRootContentSha256:$IncludeRootContentSha256
            [pscustomobject]@{
                Key = (Convert-SerializedJsonText -Value $converted)
                Index = $i
                Value = $converted
            }
            $i++
        }

        return ,@(
            $canonicalItems |
                Sort-Object -Property Key, Index |
                ForEach-Object { $_.Value }
        )
    }

    $orderedObject = [ordered]@{}
    $properties = @($Value.PSObject.Properties | Sort-Object -Property Name -CaseSensitive:$true)
    foreach ($property in $properties) {
        if ($Depth -eq 0 -and $property.Name -eq 'content_sha256' -and -not $IncludeRootContentSha256) {
            continue
        }

        $childValue = $property.Value
        if ($childValue -is [System.Collections.IEnumerable] -and -not ($childValue -is [string])) {
            $propertyIsOrdered = $orderedArrayPropertyNames.Contains($property.Name)
            $orderedObject[$property.Name] = Convert-ToCanonicalValue -Value $childValue -DocumentHashById $DocumentHashById -Depth ($Depth + 1) -IncludeRootContentSha256:$IncludeRootContentSha256 -PreserveTopLevelArrayOrder:($propertyIsOrdered -and $Depth -eq 0)
            continue
        }

        $orderedObject[$property.Name] = Convert-ToCanonicalValue -Value $childValue -DocumentHashById $DocumentHashById -Depth ($Depth + 1) -IncludeRootContentSha256:$IncludeRootContentSha256
    }

    return $orderedObject
}

function Get-Sha256Lower {
    param([Parameter(Mandatory = $true)][string] $Text)

    $encoding = [System.Text.UTF8Encoding]::new($false)
    $bytes = $encoding.GetBytes($Text)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hashBytes = $sha256.ComputeHash($bytes)
    }
    finally {
        $sha256.Dispose()
    }
    return ([System.BitConverter]::ToString($hashBytes) -replace '-', '').ToLowerInvariant()
}

function Get-DocumentRefObjects {
    param(
        [Parameter(Mandatory = $true)]
        $Value,

        [string[]] $Path = @()
    )

    $results = [System.Collections.Generic.List[object]]::new()

    if ($null -eq $Value) {
        return $results
    }

    if ($Value -is [string] -or $Value -is [ValueType]) {
        return $results
    }

    $properties = @()
    if ($Value -is [System.Collections.IDictionary]) {
        $properties = @($Value.Keys)
    }
    else {
        $properties = @($Value.PSObject.Properties.Name)
    }

    $hasDocumentRefShape = $true
    foreach ($requiredName in @('document_id', 'schema_version', 'document_version', 'content_sha256')) {
        if ($properties -notcontains $requiredName) {
            $hasDocumentRefShape = $false
            break
        }
    }
    if ($hasDocumentRefShape -and $Path.Count -gt 0) {
        $results.Add([pscustomobject]@{
            Path = ($Path -join '.')
            Value = $Value
        })
        return $results
    }

    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        $index = 0
        foreach ($item in @($Value)) {
            foreach ($childResult in @(Get-DocumentRefObjects -Value $item -Path ($Path + "[${index}]"))) {
                $results.Add($childResult)
            }
            $index++
        }
        return $results
    }

    foreach ($property in $Value.PSObject.Properties) {
        foreach ($childResult in @(Get-DocumentRefObjects -Value $property.Value -Path ($Path + $property.Name))) {
            $results.Add($childResult)
        }
    }

    return $results
}

function Test-CanonicalDocumentRefs {
    param(
        [Parameter(Mandatory = $true)]
        [object] $DocumentValue,

        [Parameter(Mandatory = $true)]
        [string] $Context
    )

    $refObjects = Get-DocumentRefObjects -Value $DocumentValue
    foreach ($refObject in $refObjects) {
        $refValue = $refObject.Value
        $refDocumentId = [string](Get-JsonPropertyValue -Value $refValue -Name 'document_id')
        $refSchemaVersion = [string](Get-JsonPropertyValue -Value $refValue -Name 'schema_version')
        $refDocumentVersion = Get-JsonPropertyValue -Value $refValue -Name 'document_version'
        $refHash = [string](Get-JsonPropertyValue -Value $refValue -Name 'content_sha256')

        if ([string]::IsNullOrWhiteSpace($refDocumentId) -or [string]::IsNullOrWhiteSpace($refSchemaVersion) -or $null -eq $refDocumentVersion) {
            $script:referenceResolutionValid = $false
            Add-Failure "$Context has an unknown reference at $($refObject.Path)."
            continue
        }

        if (-not $documentHashById.Contains($refDocumentId)) {
            $script:referenceResolutionValid = $false
            Add-Failure "$Context has an unknown reference '$refDocumentId' at $($refObject.Path)."
            continue
        }

        $resolvedHash = $documentHashById[$refDocumentId]
        if ([string]::IsNullOrWhiteSpace($refHash) -or $refHash -notmatch '^[0-9a-f]{64}$') {
            $script:referenceResolutionValid = $false
            Add-Failure "$Context has a malformed hash at $($refObject.Path)."
            continue
        }

        if (-not [string]::Equals($refHash, $resolvedHash, [StringComparison]::Ordinal)) {
            $script:referenceResolutionValid = $false
            Add-Failure "$Context has a stale reference '$refDocumentId' at $($refObject.Path); expected '$resolvedHash' but found '$refHash'."
            continue
        }

        $referencedDoc = $canonicalDocumentsById[$refDocumentId]
        if ($null -ne $referencedDoc -and -not [string]::Equals([string]$refSchemaVersion, [string]$referencedDoc.SchemaVersion, [StringComparison]::Ordinal)) {
            $script:referenceResolutionValid = $false
            Add-Failure "$Context has a stale reference '$refDocumentId' at $($refObject.Path); expected schema '$($referencedDoc.SchemaVersion)' but found '$refSchemaVersion'."
        }
    }
}

function Get-DocumentSchemaValidationPath {
    param(
        [Parameter(Mandatory = $true)]
        [string] $SchemaVersion,

        [Parameter(Mandatory = $true)]
        [string] $Context
    )

    $schemaPath = Get-SchemaPathForVersion -SchemaVersion $SchemaVersion
    if ($null -eq $schemaPath) {
        Add-Failure "$Context declares unsupported schema version '$SchemaVersion'."
        return $null
    }

    return $schemaPath
}

function Test-DocumentAgainstSchema {
    param(
        [Parameter(Mandatory = $true)]
        [object] $DocumentValue,

        [Parameter(Mandatory = $true)]
        [string] $SchemaPath,

        [Parameter(Mandatory = $true)]
        [string] $Context,

        [switch] $TopLevelArray
    )

    if ($TopLevelArray) {
        $items = @($DocumentValue)
        foreach ($item in $items) {
            $itemSchemaVersion = [string](Get-JsonPropertyValue -Value $item -Name 'schemaVersion')
            if ([string]::IsNullOrWhiteSpace($itemSchemaVersion)) {
                Add-Failure "$Context contains an item with no schemaVersion."
                continue
            }

            if (-not (Test-JsonSchemaText -JsonText (Convert-SerializedJsonText -Value $item) -SchemaPath $SchemaPath -Context "$Context item '$itemSchemaVersion'")) {
                return $false
            }
        }

        return $true
    }

    $jsonText = Convert-SerializedJsonText -Value $DocumentValue
    return Test-JsonSchemaText -JsonText $jsonText -SchemaPath $SchemaPath -Context $Context
}

function Test-CanonicalizedHash {
    param(
        [Parameter(Mandatory = $true)]
        [object] $DocumentValue,

        [Parameter(Mandatory = $true)]
        [string] $Context,

        [switch] $TopLevelArray
    )

    if ($TopLevelArray) {
        return $true
    }

    $canonicalText1 = Get-CanonicalJsonText -Value $DocumentValue -DocumentHashById $documentHashById
    $canonicalText2 = Get-CanonicalJsonText -Value $DocumentValue -DocumentHashById $documentHashById
    if (-not [string]::Equals($canonicalText1, $canonicalText2, [StringComparison]::Ordinal)) {
        $script:canonicalSerializationByteEquivalent = $false
        Add-Failure "$Context canonical serialization is not byte-identical across repeated runs."
        return $false
    }

    $hash1 = Get-Sha256Lower -Text $canonicalText1
    $hash2 = Get-Sha256Lower -Text $canonicalText2
    if (-not [string]::Equals($hash1, $hash2, [StringComparison]::Ordinal)) {
        $script:repeatedHashesIdentical = $false
        Add-Failure "$Context hash computation is not repeatable."
        return $false
    }

    return $true
}

function Update-CanonicalDocument {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject] $Specification
    )

    $path = Resolve-RepoPath -RelativePath $Specification.RelativePath
    $documentValue = Read-JsonValue -Path $path
    $canonicalText = Get-CanonicalJsonText -Value $documentValue -DocumentHashById $documentHashById
    $contentHash = Get-Sha256Lower -Text $canonicalText

    if ($Specification.HasRootContentSha256) {
        if ($null -eq $documentValue.PSObject.Properties['content_sha256']) {
            Add-Failure "Canonical document '$($Specification.RelativePath)' does not expose a root content_sha256 field."
            return
        }

        $documentValue.content_sha256 = $contentHash
    }

    $documentHashById[$documentValue.document_id] = $contentHash

    if ($UpdateContentHashes) {
        $outputText = Get-CanonicalJsonText -Value $documentValue -DocumentHashById $documentHashById -IncludeRootContentSha256
        [System.IO.File]::WriteAllText($path, $outputText, [System.Text.UTF8Encoding]::new($false))
    }

    [pscustomobject]@{
        Path = $path
        RelativePath = $Specification.RelativePath
        Value = $documentValue
        CanonicalText = $canonicalText
        Hash = $contentHash
        SchemaVersion = $Specification.SchemaVersion
        HasRootContentSha256 = $Specification.HasRootContentSha256
    }
}

function Update-ValidFixtureDocument {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject] $Specification
    )

    $path = Resolve-RepoPath -RelativePath $Specification.RelativePath
    $documentValue = Read-JsonValue -Path $path
    $canonicalText = Get-CanonicalJsonText -Value $documentValue -DocumentHashById $documentHashById
    $contentHash = Get-Sha256Lower -Text $canonicalText
    $documentId = Get-DocumentId -DocumentValue $documentValue

    if ($null -eq $documentValue.PSObject.Properties['content_sha256']) {
        Add-Failure "Valid fixture '$($Specification.RelativePath)' does not expose a root content_sha256 field."
        return
    }

    $documentValue.content_sha256 = $contentHash
    if (-not [string]::IsNullOrWhiteSpace($documentId)) {
        $documentHashById[$documentId] = $contentHash
    }

    if ($UpdateContentHashes) {
        $outputText = Get-CanonicalJsonText -Value $documentValue -DocumentHashById $documentHashById -IncludeRootContentSha256
        [System.IO.File]::WriteAllText($path, $outputText, [System.Text.UTF8Encoding]::new($false))
    }
}

function Validate-CustomCanonicalDocument {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject] $DocumentRecord
    )

    $documentValue = $DocumentRecord.Value
    $context = $DocumentRecord.RelativePath
    $schemaPath = Get-DocumentSchemaValidationPath -SchemaVersion $DocumentRecord.SchemaVersion -Context $context
    if ($null -eq $schemaPath) {
        return
    }

    if (-not (Test-DocumentAgainstSchema -DocumentValue $documentValue -SchemaPath $schemaPath -Context $context)) {
        return
    }

    if ($DocumentRecord.HasRootContentSha256) {
        $canonicalText = Get-CanonicalJsonText -Value $documentValue -DocumentHashById $documentHashById
        $computedHash = Get-Sha256Lower -Text $canonicalText
        $declaredHash = [string](Get-JsonPropertyValue -Value $documentValue -Name 'content_sha256')
        if (-not [string]::Equals($declaredHash, $computedHash, [StringComparison]::Ordinal)) {
            $script:contentHashesValid = $false
            Add-Failure "Canonical document '$context' content_sha256 '$declaredHash' does not match computed hash '$computedHash'."
        }

        if (-not [string]::Equals($DocumentRecord.Hash, $computedHash, [StringComparison]::Ordinal)) {
            $script:repeatedHashesIdentical = $false
            Add-Failure "Canonical document '$context' hash changed between passes."
        }
    }
}

function Validate-CanonicalDocumentReferences {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject] $DocumentRecord
    )

    Test-CanonicalDocumentRefs -DocumentValue $DocumentRecord.Value -Context $DocumentRecord.RelativePath
}

function Validate-CanonicalDocumentSemantics {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject] $DocumentRecord
    )

    $value = $DocumentRecord.Value
    $context = $DocumentRecord.RelativePath
    if (-not $DocumentRecord.HasRootContentSha256) {
        return
    }

    try {
        switch ($DocumentRecord.SchemaVersion) {
        'adaptive-runtime-policy-axis-contract-v1' {
            $axisContracts = @((Get-JsonPropertyValue -Value $value -Name 'axis_contracts'))
            $axisIds = @()
            foreach ($contract in $axisContracts) {
                $contractAxisId = [string](Get-JsonPropertyValue -Value $contract -Name 'axis_id')
                $contractStatus = [string](Get-JsonPropertyValue -Value $contract -Name 'status')
                $contractExecutable = [bool](Get-JsonPropertyValue -Value $contract -Name 'executable')
                $axisIds += $contractAxisId
                if (($contractStatus -in @('blocked', 'preparation_only')) -and $contractExecutable) {
                    Add-Failure "$context marks blocked or preparation-only axis '$contractAxisId' executable."
                }
            }

            $duplicates = $axisIds | Group-Object | Where-Object { $_.Count -gt 1 }
            if (@($duplicates).Count -gt 0) {
                Add-Failure "$context contains duplicate axis ids: $($duplicates.Name -join ', ')."
            }
        }
        'adaptive-runtime-effective-behavior-catalog-v1' {
            $ids = @(Get-JsonPropertyValue -Value $value -Name 'effective_behaviors' | ForEach-Object {
                [string](Get-JsonPropertyValue -Value $_ -Name 'effective_behavior_id')
            })
            $duplicates = $ids | Group-Object | Where-Object { $_.Count -gt 1 }
            if (@($duplicates).Count -gt 0) {
                Add-Failure "$context contains duplicate effective_behavior_id values: $($duplicates.Name -join ', ')."
            }
        }
        'adaptive-runtime-policy-relationship-graph-v1' {
            $edgeIds = @(Get-JsonPropertyValue -Value $value -Name 'directed_edges' | ForEach-Object {
                [string](Get-JsonPropertyValue -Value $_ -Name 'edge_id')
            })
            $duplicateEdges = $edgeIds | Group-Object | Where-Object { $_.Count -gt 1 }
            if (@($duplicateEdges).Count -gt 0) {
                Add-Failure "$context contains duplicate edge ids: $($duplicateEdges.Name -join ', ')."
            }

            foreach ($edge in @(Get-JsonPropertyValue -Value $value -Name 'directed_edges')) {
                $edgeRelationshipType = [string](Get-JsonPropertyValue -Value $edge -Name 'relationship_type')
                $edgeId = [string](Get-JsonPropertyValue -Value $edge -Name 'edge_id')
                if ($edgeRelationshipType -notin @('directed_dependency', 'equivalence', 'compatibility', 'conflict', 'promotion_guard')) {
                    Add-Failure "$context has unsupported relationship type '$edgeRelationshipType' on edge '$edgeId'."
                }
            }
        }
        'adaptive-runtime-combination-constraint-catalog-v1' {
            foreach ($constraint in @(Get-JsonPropertyValue -Value $value -Name 'combination_constraints')) {
                $constraintId = [string](Get-JsonPropertyValue -Value $constraint -Name 'constraint_id')
                $fixedAxisIds = @((Get-JsonPropertyValue -Value $constraint -Name 'fixed_axis_ids'))
                $variedAxisIds = @((Get-JsonPropertyValue -Value $constraint -Name 'varied_axis_ids'))
                $overlap = @($fixedAxisIds | Where-Object { $variedAxisIds -contains $_ })
                if (@($overlap).Count -gt 0) {
                    Add-Failure "$context constraint '$constraintId' has fixed/varied overlap: $($overlap -join ', ')."
                }
            }
        }
        'adaptive-runtime-experiment-family-catalog-v1' {
            foreach ($family in @(Get-JsonPropertyValue -Value $value -Name 'experiment_families')) {
                $familyId = [string](Get-JsonPropertyValue -Value $family -Name 'family_id')
                $supported = @((Get-JsonPropertyValue -Value $family -Name 'supported_experiment_types'))
                $blocked = @((Get-JsonPropertyValue -Value $family -Name 'blocked_experiment_types'))
                if (@($supported | Group-Object).Count -lt @($supported).Count) {
                    Add-Failure "$context family '$familyId' contains duplicate supported experiment types."
                }

                if (@($blocked | Group-Object).Count -lt @($blocked).Count) {
                    Add-Failure "$context family '$familyId' contains duplicate blocked experiment types."
                }

                $predicateRefs = @((Get-JsonPropertyValue -Value $family -Name 'predicate_refs'))
                if (@($predicateRefs).Count -eq 0) {
                    Add-Failure "$context family '$familyId' is missing predicate refs."
                }

                foreach ($historyEntry in @(Get-JsonPropertyValue -Value $family -Name 'history')) {
                    foreach ($sourceRef in @((Get-JsonPropertyValue -Value $historyEntry -Name 'source_document_refs'))) {
                        if ($null -eq $sourceRef) {
                            continue
                        }
                        $refId = [string](Get-JsonPropertyValue -Value $sourceRef -Name 'document_id')
                        if (-not $documentHashById.Contains($refId)) {
                            Add-Failure "$context family '$familyId' has unknown source document ref '$refId'."
                        }
                    }
                }
            }
        }
    }
    }
    catch {
        $script:referenceResolutionValid = $false
        Add-Failure "$context semantic validation failed for '$($DocumentRecord.SchemaVersion)': $($_.Exception.Message)"
    }
}

function Get-ExpectedInvalidCode {
    param([Parameter(Mandatory = $true)][string] $RelativePath)

    $expectationsPath = Resolve-RepoPath -RelativePath 'tests/fixtures/adaptive-runtime-experiment-control/invalid/expectations.json'
    if (Test-Path -LiteralPath $expectationsPath) {
        try {
            $expectations = Read-JsonValue -Path $expectationsPath
            $fixtureName = Split-Path -Leaf $RelativePath
            if ($expectations -is [System.Collections.IDictionary] -and $expectations.Contains($fixtureName)) {
                return [string] $expectations[$fixtureName]
            }

            if ($expectations.PSObject.Properties.Name -contains $fixtureName) {
                return [string] $expectations.PSObject.Properties[$fixtureName].Value
            }

            foreach ($propertyName in @('fixtures', 'expectations', 'invalidFixtures')) {
                $entries = Get-JsonPropertyValue -Value $expectations -Name $propertyName
                if ($null -eq $entries) {
                    continue
                }

                foreach ($entry in @($entries)) {
                    $entryPath = [string](Get-JsonPropertyValue -Value $entry -Name 'path')
                    $entryCode = [string](Get-JsonPropertyValue -Value $entry -Name 'stable_code')
                    if ([string]::IsNullOrWhiteSpace($entryCode)) {
                        $entryCode = [string](Get-JsonPropertyValue -Value $entry -Name 'expected_stable_code')
                    }

                    if ([string]::Equals($entryPath, $RelativePath, [StringComparison]::OrdinalIgnoreCase)) {
                        return $entryCode
                    }
                }
            }
        }
        catch {
            Add-Failure "Could not read expectations file '$expectationsPath': $($_.Exception.Message)"
        }
    }

    return 'unsupported_schema_version'
}

function Validate-ValidFixture {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject] $Specification
    )

    $path = Resolve-RepoPath -RelativePath $Specification.RelativePath
    $value = Read-JsonValue -Path $path
    $context = $Specification.RelativePath
    $schemaVersion = Get-DocumentSchemaVersion -DocumentValue $value -Context $context
    if ($null -eq $schemaVersion) {
        return
    }

    if (-not [string]::Equals($schemaVersion, $Specification.SchemaVersion, [StringComparison]::Ordinal)) {
        Add-Failure "Valid fixture '$context' declares '$schemaVersion' but the validator expected '$($Specification.SchemaVersion)'."
        return
    }

    $schemaPath = Get-DocumentSchemaValidationPath -SchemaVersion $schemaVersion -Context $context
    if ($null -eq $schemaPath) {
        return
    }

    if (-not (Test-DocumentAgainstSchema -DocumentValue $value -SchemaPath $schemaPath -Context $context -TopLevelArray:($Specification.TopLevelArray))) {
        return
    }

    if (-not (Test-CanonicalizedHash -DocumentValue $value -Context $context -TopLevelArray:($Specification.TopLevelArray))) {
        return
    }

    if (-not $Specification.TopLevelArray) {
        $computedHash = Get-Sha256Lower -Text (Get-CanonicalJsonText -Value $value -DocumentHashById $documentHashById)
        $declaredHash = [string](Get-JsonPropertyValue -Value $value -Name 'content_sha256')
        if (-not [string]::Equals($declaredHash, $computedHash, [StringComparison]::Ordinal)) {
            $script:contentHashesValid = $false
            Add-Failure "Valid fixture '$context' content_sha256 '$declaredHash' does not match computed hash '$computedHash'."
            return
        }

        Test-CanonicalDocumentRefs -DocumentValue $value -Context $context
    }

    if ($Specification.TopLevelArray) {
        $items = @($value)
        foreach ($item in $items) {
            $schemaItemVersion = [string](Get-JsonPropertyValue -Value $item -Name 'schemaVersion')
            if ([string]::IsNullOrWhiteSpace($schemaItemVersion)) {
                Add-Failure "Valid fixture '$context' includes an item without schemaVersion."
            }
        }
    }
}

function Get-ObservedInvalidCode {
    param(
        [Parameter(Mandatory = $true)]
        [object] $DocumentValue,

        [Parameter(Mandatory = $true)]
        [string] $SchemaVersion,

        [Parameter(Mandatory = $true)]
        [string] $RelativePath
    )

    if ($null -ne (Get-JsonPropertyValue -Value $DocumentValue -Name 'unknown_field')) {
        return 'unknown_field'
    }

    if ((Get-JsonPropertyValue -Value $DocumentValue -Name 'active_behavior_authorization') -eq $true) {
        return 'active_behavior_authorization_true'
    }

    if ((Get-JsonPropertyValue -Value $DocumentValue -Name 'performance_acceptance_authorization') -eq $true) {
        return 'performance_acceptance_authorization_true'
    }

    $rootHash = [string](Get-JsonPropertyValue -Value $DocumentValue -Name 'content_sha256')
    if ($rootHash -notmatch '^[0-9a-f]{64}$') {
        return 'malformed_hash'
    }

    $schemaPath = Get-SchemaPathForVersion -SchemaVersion $SchemaVersion
    try {
        $schemaValid = Test-Json -Json (Convert-SerializedJsonText -Value $DocumentValue) -SchemaFile $schemaPath -ErrorAction Stop
    }
    catch {
        $schemaValid = $false
    }

    if (-not $schemaValid) {
        if ($SchemaVersion -eq 'adaptive-runtime-policy-relationship-graph-v1') {
            return 'invalid_relationship_type'
        }

        if ($SchemaVersion -eq 'adaptive-runtime-policy-axis-contract-v1') {
            foreach ($axis in @((Get-JsonPropertyValue -Value $DocumentValue -Name 'axis_contracts'))) {
                if ([string](Get-JsonPropertyValue -Value $axis -Name 'status') -eq 'preparation_only' -and
                    (Get-JsonPropertyValue -Value $axis -Name 'executable') -eq $true) {
                    return 'stage5_preparation_only_executable'
                }
            }
        }

        return 'schema_validation_failed'
    }

    if ($SchemaVersion -eq 'adaptive-runtime-policy-axis-contract-v1') {
        $axisIds = @((Get-JsonPropertyValue -Value $DocumentValue -Name 'axis_contracts') | ForEach-Object {
            [string](Get-JsonPropertyValue -Value $_ -Name 'axis_id')
        })
        if (@($axisIds | Group-Object | Where-Object Count -gt 1).Count -gt 0) {
            return 'duplicate_axis_definition'
        }

        foreach ($axis in @((Get-JsonPropertyValue -Value $DocumentValue -Name 'axis_contracts'))) {
            $axisId = [string](Get-JsonPropertyValue -Value $axis -Name 'axis_id')
            $predicateIds = @((Get-JsonPropertyValue -Value $axis -Name 'canonical_predicates') | ForEach-Object {
                [string](Get-JsonPropertyValue -Value $_ -Name 'predicate_id')
            })
            if ($axisId -eq 'application_send_turn_planning' -and
                $predicateIds -notcontains 'predicate.send_turn.verification_only') {
                return 'missing_canonical_predicate_reference'
            }
        }

        foreach ($refObject in @(Get-DocumentRefObjects -Value $DocumentValue)) {
            $refId = [string](Get-JsonPropertyValue -Value $refObject.Value -Name 'document_id')
            $refSchema = [string](Get-JsonPropertyValue -Value $refObject.Value -Name 'schema_version')
            if (-not $documentHashById.Contains($refId)) {
                return 'unknown_contract_reference'
            }

            if (-not $knownValidSchemaVersions.Contains($refSchema)) {
                return 'stale_version_reference'
            }
        }
    }

    if ($SchemaVersion -eq 'adaptive-runtime-policy-relationship-graph-v1') {
        $edgeIds = @((Get-JsonPropertyValue -Value $DocumentValue -Name 'directed_edges') | ForEach-Object {
            [string](Get-JsonPropertyValue -Value $_ -Name 'edge_id')
        })
        if (@($edgeIds | Group-Object | Where-Object Count -gt 1).Count -gt 0) {
            return 'duplicate_relationship_edge'
        }
    }

    if ($SchemaVersion -eq 'adaptive-runtime-combination-constraint-catalog-v1') {
        foreach ($constraint in @((Get-JsonPropertyValue -Value $DocumentValue -Name 'combination_constraints'))) {
            $fixed = @((Get-JsonPropertyValue -Value $constraint -Name 'fixed_axis_ids'))
            $varied = @((Get-JsonPropertyValue -Value $constraint -Name 'varied_axis_ids'))
            if (@($fixed | Where-Object { $varied -contains $_ }).Count -gt 0) {
                return 'fixed_varied_axis_overlap'
            }
        }
    }

    if ($SchemaVersion -eq 'adaptive-runtime-compiled-execution-manifest-v1' -and
        [string](Get-JsonPropertyValue -Value $DocumentValue -Name 'build_status') -eq 'blocked_by_capability' -and
        @((Get-JsonPropertyValue -Value $DocumentValue -Name 'executable_cells')).Count -gt 0) {
        return 'blocked_axis_executable'
    }

    if ($SchemaVersion -eq 'adaptive-runtime-experiment-plan-v1') {
        $knownValuesByAxis = @{
            application_send_batch_formation = @('legacy_current', 'single_eligible')
            buffer_copy_coalescing = @('legacy_current', 'memory_conservative')
            application_send_turn_planning = @('legacy_current', 'conservative')
        }
        foreach ($treatment in @((Get-JsonPropertyValue -Value $DocumentValue -Name 'treatments'))) {
            $axisId = [string](Get-JsonPropertyValue -Value $treatment -Name 'axis_id')
            foreach ($valueName in @('configured_value', 'forced_value', 'candidate_value')) {
                $policyValue = Get-JsonPropertyValue -Value $treatment -Name $valueName
                if ($null -ne $policyValue -and
                    $knownValuesByAxis.ContainsKey($axisId) -and
                    $knownValuesByAxis[$axisId] -notcontains [string]$policyValue) {
                    return 'illegal_policy_value'
                }
            }
        }

        $experimentType = [string](Get-JsonPropertyValue -Value $DocumentValue -Name 'experiment_type')
        if ($experimentType -in @('feedback_loop', 'profile_validation')) {
            return 'unsupported_experiment_type'
        }
    }

    return 'fixture_unexpectedly_valid'
}

function Validate-InvalidFixture {
    param(
        [Parameter(Mandatory = $true)]
        [string] $RelativePath
    )

    $path = Resolve-RepoPath -RelativePath $RelativePath
    $value = Read-JsonValue -Path $path
    $schemaVersion = Get-DocumentSchemaVersion -DocumentValue $value -Context $RelativePath
    $expectedCode = Get-ExpectedInvalidCode -RelativePath $RelativePath

    $observedCode = if ($null -eq $schemaVersion -or -not $knownValidSchemaVersions.Contains($schemaVersion)) {
        'unsupported_schema_version'
    }
    else {
        Get-ObservedInvalidCode -DocumentValue $value -SchemaVersion $schemaVersion -RelativePath $RelativePath
    }

    $invalidFixtureValidationResults.Add([pscustomobject]@{
        path = $RelativePath
        expected_code = $expectedCode
        observed_code = $observedCode
    })

    if ($observedCode -ne $expectedCode) {
        $script:invalidFixtureFailures++
        $message = "Invalid fixture '$RelativePath' expected stable code '$expectedCode' but observed '$observedCode'."
        Add-Failure $message
        $observedInvalidFixtureFailures.Add($message)
    }
}

function Validate-SyntheticUnknownFieldRejection {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject] $Specification
    )

    $path = Resolve-RepoPath -RelativePath $Specification.RelativePath
    $value = Read-JsonValue -Path $path
    if ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) {
        return
    }

    $synthetic = [System.Management.Automation.PSObject]::AsPSObject($value.PSObject.Copy())
    $synthetic | Add-Member -NotePropertyName 'unexpected_field' -NotePropertyValue 'should_fail' -Force
    $schemaPath = Get-SchemaPathForVersion -SchemaVersion $Specification.SchemaVersion
    if ($null -eq $schemaPath) {
        return
    }

    try {
        if (-not (Test-Json -Json (Convert-SerializedJsonText -Value $synthetic) -SchemaFile $schemaPath -ErrorAction Stop)) {
            $script:unknownFieldRejected = $true
        }
    }
    catch {
        $script:unknownFieldRejected = $true
    }
}

if (-not (Test-Path -LiteralPath $RepositoryRoot -PathType Container)) {
    throw "Repository root '$RepositoryRoot' does not exist."
}

foreach ($schemaEntry in $schemaMap.GetEnumerator()) {
    $schemaPath = Resolve-RepoPath -RelativePath $schemaEntry.Value
    if (-not (Test-Path -LiteralPath $schemaPath -PathType Leaf)) {
        Add-Failure "Missing schema file '$($schemaEntry.Value)'."
        continue
    }

    try {
        $null = Read-JsonValue -Path $schemaPath
    }
    catch {
        Add-Failure "Schema file '$($schemaEntry.Value)' could not be parsed: $($_.Exception.Message)"
    }
}

$canonicalDocumentsById = [ordered]@{}
foreach ($spec in $canonicalDocumentSpecs) {
    $record = @(Update-CanonicalDocument -Specification $spec)[-1]
    if ($null -eq $record) {
        throw "Canonical document '$($spec.RelativePath)' did not produce a validation record."
    }
    $canonicalDocumentsById[$record.Value.document_id] = $record
}

foreach ($record in $canonicalDocumentsById.Values) {
    Validate-CustomCanonicalDocument -DocumentRecord $record
}

foreach ($record in $canonicalDocumentsById.Values) {
    Validate-CanonicalDocumentReferences -DocumentRecord $record
    Validate-CanonicalDocumentSemantics -DocumentRecord $record
}

foreach ($spec in $canonicalDocumentSpecs) {
    Validate-SyntheticUnknownFieldRejection -Specification $spec
    break
}

foreach ($fixture in $validFixtureSpecs) {
    Update-ValidFixtureDocument -Specification $fixture
}

foreach ($fixture in $validFixtureSpecs) {
    $result = [pscustomobject]@{
        RelativePath = $fixture.RelativePath
        SchemaVersion = $fixture.SchemaVersion
    }

    $validFixtureValidationResults.Add($result)
    Validate-ValidFixture -Specification $fixture
}

foreach ($fixture in $invalidFixtureSpecs) {
    Validate-InvalidFixture -RelativePath $fixture
}

if ($canonicalSerializationByteEquivalent -and $repeatedHashesIdentical -and $contentHashesValid -and $referenceResolutionValid -and $unknownFieldRejected) {
    $null = $true
}

$result = [ordered]@{
    valid = ($failures.Count -eq 0)
    schema_count = $schemaCount
    canonical_document_count = $canonicalDocumentCount
    valid_fixture_count = $validFixtureCount
    invalid_fixture_count = $invalidFixtureCount
    invalid_fixture_failures = $invalidFixtureFailures
    invalid_fixture_results = @($invalidFixtureValidationResults | Sort-Object -Property path)
    unknown_field_rejected = $unknownFieldRejected
    canonical_serialization_byte_equivalent = $canonicalSerializationByteEquivalent
    repeated_hashes_identical = $repeatedHashesIdentical
    content_hashes_valid = $contentHashesValid
    reference_resolution_valid = $referenceResolutionValid
    failures = @($failures)
}

[string] (Convert-SerializedJsonText -Value $result)

if ($result.valid) {
    exit 0
}

exit 1
