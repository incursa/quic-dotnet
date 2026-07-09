<#
.SYNOPSIS
Creates or verifies ProtocolLab public-report bundles for completed controller jobs.

.DESCRIPTION
This helper is intentionally a thin wrapper over the ProtocolLab controller
publication endpoint. It defaults to dry-run mode so package-backed controller
results can be checked for durable dashboard readiness without uploading to R2
or enqueueing site import. Use -Publish only when the publication target and
controller secrets are intentionally configured.
#>
[CmdletBinding(PositionalBinding = $false)]
param(
    [string] $ControllerUrl = "http://localhost:5088",

    [string] $ProtocolLabRoot = $(if ($env:PROTOCOL_LAB_PUBLICATION_ROOT) { $env:PROTOCOL_LAB_PUBLICATION_ROOT } else { "/opt/protocol-lab/protocol-lab-internal" }),

    [Parameter(Mandatory = $true)]
    [string[]] $JobId,

    [switch] $Publish,

    [switch] $DisallowDiagnosticPublication,

    [switch] $VerifyUploadedObjects,

    [string] $SiteEnqueueEndpoint,

    [string] $OutputRoot = ".artifacts\perf-publication",

    [string] $RunId = "quic-publication-$((Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'))"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-FullPath {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,

        [Parameter(Mandatory = $true)]
        [string] $BasePath
    )

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    return [System.IO.Path]::GetFullPath((Join-Path $BasePath $Path))
}

function Get-RepoRoot {
    $candidate = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    if (-not (Test-Path -LiteralPath (Join-Path $candidate "Incursa.Quic.slnx"))) {
        throw "Could not locate quic-dotnet repository root from '$PSScriptRoot'."
    }

    return [System.IO.Path]::GetFullPath($candidate)
}

function ConvertTo-JsonObject {
    param($Value)

    if ($null -eq $Value) {
        return $null
    }

    if ($Value -is [string]) {
        return $Value
    }

    if ($Value -is [System.Collections.IDictionary]) {
        $output = [ordered]@{}
        foreach ($key in $Value.Keys) {
            $output[[string]$key] = ConvertTo-JsonObject -Value $Value[$key]
        }

        return $output
    }

    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        return @($Value | ForEach-Object { ConvertTo-JsonObject -Value $_ })
    }

    if ($Value -is [pscustomobject]) {
        $output = [ordered]@{}
        foreach ($property in $Value.PSObject.Properties) {
            $output[$property.Name] = ConvertTo-JsonObject -Value $property.Value
        }

        return $output
    }

    return $Value
}

function Write-JsonFile {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,

        [Parameter(Mandatory = $true)]
        $Value
    )

    $directory = Split-Path -Path $Path -Parent
    if (-not [string]::IsNullOrWhiteSpace($directory)) {
        New-Item -ItemType Directory -Force -Path $directory | Out-Null
    }

    $Value | ConvertTo-Json -Depth 80 | Set-Content -LiteralPath $Path -Encoding utf8NoBOM
}

function Invoke-JsonPost {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Uri,

        [Parameter(Mandatory = $true)]
        $Body
    )

    $json = $Body | ConvertTo-Json -Depth 20
    Invoke-RestMethod -Method Post -Uri $Uri -ContentType "application/json" -Body $json
}

function New-PublicationRequestBody {
    $body = [ordered]@{
        protocolLabRoot = $ProtocolLabRoot
        dryRun = -not [bool]$Publish
        allowDiagnosticPublication = -not [bool]$DisallowDiagnosticPublication
        verifyUploadedObjects = [bool]$VerifyUploadedObjects
    }

    if (-not [string]::IsNullOrWhiteSpace($SiteEnqueueEndpoint)) {
        $body["siteEnqueueEndpoint"] = $SiteEnqueueEndpoint
    }

    return $body
}

function Get-StringProperty {
    param($Object, [string] $Name)

    if ($null -eq $Object) {
        return ""
    }

    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) {
        return ""
    }

    return [string]$property.Value
}

function Expand-StringList {
    param($Value)

    foreach ($item in @($Value)) {
        if ($item -is [System.Array] -and -not ($item -is [string])) {
            foreach ($nested in @(Expand-StringList $item)) {
                $nested
            }

            continue
        }

        $text = [string]$item
        if ([string]::IsNullOrWhiteSpace($text)) {
            continue
        }

        foreach ($part in $text -split ",") {
            $trimmed = $part.Trim()
            if (-not [string]::IsNullOrWhiteSpace($trimmed)) {
                $trimmed
            }
        }
    }
}

$repoRoot = Get-RepoRoot
$outputDirectory = Resolve-FullPath -Path (Join-Path $OutputRoot $RunId) -BasePath $repoRoot
$requestBody = New-PublicationRequestBody
$results = New-Object System.Collections.Generic.List[object]
$mode = if ($Publish) { "publish" } else { "dry-run" }
$jobIds = @(Expand-StringList $JobId)
if ($jobIds.Count -eq 0) {
    throw "Specify at least one job id."
}

Write-Host "ProtocolLab controller publication"
Write-Host "  controller: $ControllerUrl"
Write-Host "  protocol lab root: $ProtocolLabRoot"
Write-Host "  mode: $mode"
Write-Host "  output: $outputDirectory"

foreach ($currentJobId in $jobIds) {
    Write-Host ("{0:u} {1} publication {2}" -f [DateTimeOffset]::UtcNow, $currentJobId, $mode)
    $job = Invoke-RestMethod -Method Get -Uri "$ControllerUrl/api/lab/jobs/$currentJobId"
    $status = Get-StringProperty -Object $job -Name "status"
    if ($status -ne "completed") {
        throw "Job '$currentJobId' is '$status'; only completed controller jobs can be published."
    }

    $attempt = Invoke-JsonPost -Uri "$ControllerUrl/api/lab/jobs/$currentJobId/publication" -Body $requestBody
    $history = Invoke-RestMethod -Method Get -Uri "$ControllerUrl/api/lab/jobs/$currentJobId/publication"
    $result = [ordered]@{
        jobId = $currentJobId
        runId = Get-StringProperty -Object $job.result -Name "runId"
        runRoot = Get-StringProperty -Object $job.result -Name "runRoot"
        request = ConvertTo-JsonObject -Value $requestBody
        attempt = ConvertTo-JsonObject -Value $attempt
        history = ConvertTo-JsonObject -Value $history
    }
    $results.Add($result) | Out-Null

    Write-Host ("  attempt: {0}" -f (Get-StringProperty -Object $attempt -Name "attemptId"))
    Write-Host ("  status: {0}" -f (Get-StringProperty -Object $attempt -Name "status"))
}

$manifest = [ordered]@{
    schemaVersion = "incursa.quic.protocol-lab-publication.v1"
    generatedAt = (Get-Date).ToUniversalTime().ToString("O")
    controllerUrl = $ControllerUrl
    protocolLabRoot = $ProtocolLabRoot
    mode = $mode
    dryRun = -not [bool]$Publish
    allowDiagnosticPublication = -not [bool]$DisallowDiagnosticPublication
    verifyUploadedObjects = [bool]$VerifyUploadedObjects
    results = @($results.ToArray())
}

$manifestPath = Join-Path $outputDirectory "publication-results.json"
Write-JsonFile -Path $manifestPath -Value $manifest
Write-Host "  result: $manifestPath"

$manifest
