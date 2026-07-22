# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-AdaptiveRuntimeRepositoryRoot {
    [CmdletBinding()]
    param()

    return (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
}

function Resolve-AdaptiveRuntimePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path
    )

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    return [System.IO.Path]::GetFullPath((Join-Path (Get-Location) $Path))
}

function Get-FileSha256Hex {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path
    )

    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-StringSha256Hex {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $Value
    )

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
    $hashBytes = [System.Security.Cryptography.SHA256]::HashData($bytes)
    return ([System.Convert]::ToHexString($hashBytes)).ToLowerInvariant()
}

function Write-ValidatedJsonDocument {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object] $Document,

        [Parameter(Mandatory = $true)]
        [string] $SchemaPath,

        [Parameter(Mandatory = $true)]
        [string] $OutputPath
    )

    $resolvedSchemaPath = Resolve-AdaptiveRuntimePath -Path $SchemaPath
    $resolvedOutputPath = Resolve-AdaptiveRuntimePath -Path $OutputPath
    if (Test-Path -LiteralPath $resolvedOutputPath) {
        throw "Append-only output path already exists: $resolvedOutputPath"
    }

    $parent = Split-Path -Parent $resolvedOutputPath
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }

    $json = $Document | ConvertTo-Json -Depth 100
    if (-not ($json | Test-Json -SchemaFile $resolvedSchemaPath -ErrorAction Stop)) {
        throw "Schema validation failed for '$resolvedOutputPath' against '$resolvedSchemaPath'."
    }

    [System.IO.File]::WriteAllText(
        $resolvedOutputPath,
        $json + [System.Environment]::NewLine,
        [System.Text.UTF8Encoding]::new($false))

    return [pscustomobject]@{
        Path = $resolvedOutputPath
        Sha256 = Get-FileSha256Hex -Path $resolvedOutputPath
    }
}

function Read-ValidatedJsonDocument {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,

        [Parameter(Mandatory = $true)]
        [string] $SchemaPath
    )

    $resolvedPath = (Resolve-Path -LiteralPath $Path).Path
    $resolvedSchemaPath = Resolve-AdaptiveRuntimePath -Path $SchemaPath
    $json = Get-Content -LiteralPath $resolvedPath -Raw
    if (-not ($json | Test-Json -SchemaFile $resolvedSchemaPath -ErrorAction Stop)) {
        throw "Schema validation failed: $resolvedPath"
    }

    return [pscustomobject]@{
        Path = $resolvedPath
        Sha256 = Get-FileSha256Hex -Path $resolvedPath
        Document = $json | ConvertFrom-Json -Depth 100
    }
}

function Get-GitCommitHash {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $RepositoryRoot
    )

    $commit = (& git -C $RepositoryRoot rev-parse HEAD).Trim()
    if ([string]::IsNullOrWhiteSpace($commit)) {
        throw "Unable to resolve repository commit for '$RepositoryRoot'."
    }

    return $commit
}

function Convert-BytesToMiB {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [Nullable[double]] $Value
    )

    if ($null -eq $Value) {
        return $null
    }

    return [Math]::Round($Value / 1MB, 6)
}

function Convert-BytesToKiB {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [Nullable[double]] $Value
    )

    if ($null -eq $Value) {
        return $null
    }

    return [Math]::Round($Value / 1KB, 6)
}

function Convert-MicrosToMilliseconds {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [Nullable[double]] $Value
    )

    if ($null -eq $Value) {
        return $null
    }

    return [Math]::Round($Value / 1000.0, 6)
}

function Convert-Q16ToRatio {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [Nullable[double]] $Value
    )

    if ($null -eq $Value) {
        return $null
    }

    return [Math]::Round($Value / 65536.0, 6)
}

function Get-BitCount {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int] $Value
    )

    $count = 0
    $remaining = [uint32] $Value
    while ($remaining -ne 0) {
        $count += ($remaining -band 1)
        $remaining = $remaining -shr 1
    }

    return $count
}
