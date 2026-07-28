# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:OrderSensitiveArrayNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($name in @(
    'treatment_order',
    'treatments',
    'planned_cells',
    'expanded_configured_cells',
    'execution_order',
    'executable_cells',
    'validation_errors',
    'validation_warnings',
    'ordered_observations',
    'profile_treatment_ids',
    'notes'
)) {
    [void]$script:OrderSensitiveArrayNames.Add($name)
}

function Get-AdaptiveRuntimeJsonProperty {
    param(
        [AllowNull()][object] $Value,
        [Parameter(Mandatory = $true)][string] $Name
    )

    if ($null -eq $Value) {
        return $null
    }

    if ($Value -is [System.Collections.IDictionary]) {
        if ($Value.Contains($Name)) {
            return $Value[$Name]
        }
        return $null
    }

    $property = $Value.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }
    return $property.Value
}

function ConvertTo-AdaptiveRuntimeCanonicalValue {
    param(
        [Parameter(Mandatory = $true)][AllowNull()][object] $Value,
        [int] $Depth = 0,
        [switch] $IncludeRootContentSha256,
        [switch] $PreserveArrayOrder
    )

    if ($null -eq $Value) {
        return $null
    }

    if ($Value -is [string] -or $Value -is [bool] -or
        $Value -is [byte] -or $Value -is [sbyte] -or
        $Value -is [int16] -or $Value -is [uint16] -or
        $Value -is [int32] -or $Value -is [uint32] -or
        $Value -is [int64] -or $Value -is [uint64] -or
        $Value -is [single] -or $Value -is [double] -or
        $Value -is [decimal]) {
        return $Value
    }

    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string]) -and
        -not ($Value -is [System.Collections.IDictionary])) {
        $canonicalItems = [System.Collections.Generic.List[object]]::new()
        $index = 0
        foreach ($item in @($Value)) {
            $converted = ConvertTo-AdaptiveRuntimeCanonicalValue -Value $item -Depth ($Depth + 1)
            $canonicalItems.Add([pscustomobject]@{
                Key = ($converted | ConvertTo-Json -Depth 100 -Compress)
                Index = $index
                Value = $converted
            })
            $index++
        }

        if ($PreserveArrayOrder) {
            return ,@($canonicalItems | Sort-Object Index | ForEach-Object Value)
        }

        return ,@($canonicalItems | Sort-Object Key, Index | ForEach-Object Value)
    }

    $propertyNames = if ($Value -is [System.Collections.IDictionary]) {
        @($Value.Keys)
    }
    else {
        @($Value.PSObject.Properties.Name)
    }

    if ($Depth -gt 0 -and
        @('document_id','schema_version','document_version','content_sha256' |
            Where-Object { $propertyNames -notcontains $_ }).Count -eq 0) {
        return [ordered]@{
            document_id = Get-AdaptiveRuntimeJsonProperty -Value $Value -Name 'document_id'
            schema_version = Get-AdaptiveRuntimeJsonProperty -Value $Value -Name 'schema_version'
            document_version = Get-AdaptiveRuntimeJsonProperty -Value $Value -Name 'document_version'
            content_sha256 = Get-AdaptiveRuntimeJsonProperty -Value $Value -Name 'content_sha256'
        }
    }

    $result = [ordered]@{}
    foreach ($propertyName in @($propertyNames | Sort-Object -CaseSensitive)) {
        if ($Depth -eq 0 -and $propertyName -eq 'content_sha256' -and -not $IncludeRootContentSha256) {
            continue
        }

        if ($Value -is [System.Collections.IDictionary]) {
            $child = $Value[$propertyName]
        }
        else {
            $child = $Value.PSObject.Properties[$propertyName].Value
        }
        $preserveChildOrder = $Depth -eq 0 -and $script:OrderSensitiveArrayNames.Contains($propertyName)
        $result[$propertyName] = ConvertTo-AdaptiveRuntimeCanonicalValue `
            -Value $child `
            -Depth ($Depth + 1) `
            -IncludeRootContentSha256:$IncludeRootContentSha256 `
            -PreserveArrayOrder:$preserveChildOrder
    }

    return $result
}

function ConvertTo-AdaptiveRuntimeCanonicalJson {
    param(
        [Parameter(Mandatory = $true)][AllowNull()][object] $Value,
        [switch] $IncludeRootContentSha256
    )

    $canonical = ConvertTo-AdaptiveRuntimeCanonicalValue `
        -Value $Value `
        -IncludeRootContentSha256:$IncludeRootContentSha256
    return ($canonical | ConvertTo-Json -Depth 100 -Compress)
}

function Get-AdaptiveRuntimeSha256 {
    param([Parameter(Mandatory = $true)][string] $Text)

    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($Text)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([System.BitConverter]::ToString($sha256.ComputeHash($bytes)) -replace '-', '').ToLowerInvariant()
    }
    finally {
        $sha256.Dispose()
    }
}

function Get-AdaptiveRuntimeDocumentHash {
    param([Parameter(Mandatory = $true)][object] $Document)

    return Get-AdaptiveRuntimeSha256 -Text (ConvertTo-AdaptiveRuntimeCanonicalJson -Value $Document)
}

function Set-AdaptiveRuntimeDocumentHash {
    param([Parameter(Mandatory = $true)][object] $Document)

    $hash = Get-AdaptiveRuntimeDocumentHash -Document $Document
    if ($Document -is [System.Collections.IDictionary]) {
        $Document['content_sha256'] = $hash
    }
    else {
        $Document.content_sha256 = $hash
    }
    return $hash
}

function Read-AdaptiveRuntimeJsonDocument {
    param([Parameter(Mandatory = $true)][string] $Path)

    return Get-Content -LiteralPath $Path -Raw |
        ConvertFrom-Json -Depth 100 -DateKind String
}

function Write-AdaptiveRuntimeCanonicalDocument {
    param(
        [Parameter(Mandatory = $true)][object] $Document,
        [Parameter(Mandatory = $true)][string] $Path
    )

    [void](Set-AdaptiveRuntimeDocumentHash -Document $Document)
    $text = ConvertTo-AdaptiveRuntimeCanonicalJson -Value $Document -IncludeRootContentSha256
    $parent = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -LiteralPath $parent)) {
        [void](New-Item -ItemType Directory -Path $parent)
    }
    [System.IO.File]::WriteAllText($Path, $text, [System.Text.UTF8Encoding]::new($false))
}

function Test-AdaptiveRuntimeDocumentHash {
    param([Parameter(Mandatory = $true)][object] $Document)

    $declared = [string](Get-AdaptiveRuntimeJsonProperty -Value $Document -Name 'content_sha256')
    return $declared -match '^[0-9a-f]{64}$' -and
        [string]::Equals($declared, (Get-AdaptiveRuntimeDocumentHash -Document $Document), [StringComparison]::Ordinal)
}

function Test-AdaptiveRuntimeJsonSchema {
    param(
        [Parameter(Mandatory = $true)][object] $Document,
        [Parameter(Mandatory = $true)][string] $SchemaPath
    )

    $json = $Document | ConvertTo-Json -Depth 100 -Compress
    return Test-Json -Json $json -SchemaFile $SchemaPath -ErrorAction Stop
}

function Get-AdaptiveRuntimeEvidenceWarningCodes {
    param(
        [Parameter(Mandatory = $true)][object] $Evidence,
        [AllowNull()][object] $PlanValidation
    )

    $warningCodes = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)

    foreach ($group in @($Evidence.operations | Group-Object {
        "$($_.epoch_sequence)|$($_.axis_id)"
    })) {
        $behaviorIds = @(
            $group.Group |
                Where-Object {
                    -not [string]::IsNullOrWhiteSpace([string]$_.effective_behavior_id)
                } |
                ForEach-Object { [string]$_.effective_behavior_id } |
                Sort-Object -Unique
        )
        if ($behaviorIds.Count -gt 1) {
            [void]$warningCodes.Add('multiple_effective_behaviors_in_epoch')
        }
    }

    foreach ($operation in @($Evidence.operations)) {
        $retainedKinds = @(
            $Evidence.classifications |
                Where-Object {
                    [long]$_.operation_id -eq [long]$operation.operation_id -and
                    $_.retained -eq $true
                } |
                ForEach-Object { [string]$_.kind } |
                Sort-Object -Unique
        )
        if ($operation.result -eq 'inactive' -and $retainedKinds -contains 'inactive') {
            [void]$warningCodes.Add('inactive_operation_retained')
        }
        if ($operation.result -in @('fallback', 'clamped') -and
            @($retainedKinds | Where-Object { $_ -in @('fallback', 'clamped') }).Count -gt 0) {
            [void]$warningCodes.Add('fallback_operation_retained')
        }
    }

    if ($null -ne $PlanValidation -and
        [string]$PlanValidation.validation_classification -eq 'verification_only') {
        $retainedEquivalentCells = @(
            $PlanValidation.expanded_planned_cells |
                Where-Object {
                    [string]$_.execution_state -eq 'retained_for_verification'
                }
        )
        if ($retainedEquivalentCells.Count -gt 0) {
            [void]$warningCodes.Add(
                'verification_only_equivalent_cell_retained')
        }
    }
    elseif ([string]$Evidence.schema_version -eq
        'adaptive-runtime-operation-evidence-v1' -and
        @($Evidence.classifications | Where-Object {
            [string]$_.kind -eq 'negative' -and $_.retained -eq $true
        }).Count -gt 0) {
        # Retained v1 fixtures predate an explicit plan-validation reference.
        # Keep their content-derived compatibility classification while v2
        # requires the authoritative linked validation document.
        [void]$warningCodes.Add(
            'verification_only_equivalent_cell_retained')
    }

    return @($warningCodes | Sort-Object)
}

function New-AdaptiveRuntimeTraceReferences {
    return [ordered]@{
        requirement_ids = @(
            'REQ-QUIC-CRT-0202',
            'REQ-QUIC-CRT-0203',
            'REQ-QUIC-CRT-0204',
            'REQ-QUIC-CRT-0205'
        )
        architecture_ids = @('ARC-QUIC-CRT-0092')
        work_item_ids = @('WI-QUIC-CRT-0093')
        verification_ids = @('VER-QUIC-CRT-0094')
    }
}

Export-ModuleMember -Function @(
    'ConvertTo-AdaptiveRuntimeCanonicalJson',
    'Get-AdaptiveRuntimeDocumentHash',
    'Get-AdaptiveRuntimeJsonProperty',
    'Get-AdaptiveRuntimeSha256',
    'New-AdaptiveRuntimeTraceReferences',
    'Read-AdaptiveRuntimeJsonDocument',
    'Get-AdaptiveRuntimeEvidenceWarningCodes',
    'Set-AdaptiveRuntimeDocumentHash',
    'Test-AdaptiveRuntimeDocumentHash',
    'Test-AdaptiveRuntimeJsonSchema',
    'Write-AdaptiveRuntimeCanonicalDocument'
)
