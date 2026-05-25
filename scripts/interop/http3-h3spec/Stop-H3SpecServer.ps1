[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ServerContextPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $ServerContextPath)) {
    throw "Server context does not exist: $ServerContextPath"
}

$context = Get-Content -Raw -LiteralPath $ServerContextPath | ConvertFrom-Json
if ($context.PSObject.Properties.Name -notcontains "processId") {
    Write-Host "No processId was recorded in $ServerContextPath."
    return
}

$processId = [int]$context.processId
$process = Get-Process -Id $processId -ErrorAction SilentlyContinue
if ($null -eq $process) {
    Write-Host "HTTP/3 server process $processId is already stopped."
    return
}

Stop-Process -Id $processId -Force
Write-Host "Stopped HTTP/3 server process $processId."
