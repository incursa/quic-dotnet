# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $PlanPath,
    [string] $CatalogRoot,
    [string] $OutputPath,
    [string] $RepositoryRoot,
    [switch] $AllowInvalid
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$arguments = @{
    PlanPath = $PlanPath
    PassThru = $true
    AllowInvalid = $AllowInvalid
}
if (-not [string]::IsNullOrWhiteSpace($CatalogRoot)) { $arguments.CatalogRoot = $CatalogRoot }
if (-not [string]::IsNullOrWhiteSpace($OutputPath)) { $arguments.OutputPath = $OutputPath }
if (-not [string]::IsNullOrWhiteSpace($RepositoryRoot)) { $arguments.RepositoryRoot = $RepositoryRoot }

& (Join-Path $PSScriptRoot 'Compile-AdaptiveRuntimeExperimentPlan.ps1') @arguments
