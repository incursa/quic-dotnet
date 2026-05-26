[CmdletBinding()]
param(
    [ValidateSet('h2load', 'oha')]
    [string]$Tool = 'h2load',
    [string]$BaseUrl = 'https://localhost:4433',
    [string]$Path = '/plaintext',
    [int]$Requests = 100000,
    [int]$Connections = 256,
    [int]$Streams = 100,
    [switch]$Insecure
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$artifactRoot = Join-Path (Join-Path '.artifacts' 'http3-benchmarks') $timestamp
New-Item -ItemType Directory -Path $artifactRoot -Force | Out-Null

$url = $BaseUrl.TrimEnd('/') + '/' + $Path.TrimStart('/')
$safePath = ($Path.Trim('/').Replace('/', '_'))
if ([string]::IsNullOrWhiteSpace($safePath)) {
    $safePath = 'root'
}

switch ($Tool) {
    'h2load' {
        $arguments = @('--h3', '-n', $Requests.ToString(), '-c', $Connections.ToString(), '-m', $Streams.ToString(), $url)
        if ($Insecure) {
            $arguments = @('-k') + $arguments
        }
    }
    'oha' {
        $arguments = @('--http-version', '3', '-n', $Requests.ToString(), '-c', $Connections.ToString(), $url)
        if ($Insecure) {
            $arguments = @('--disable-tls-verify') + $arguments
        }
    }
}

$outputPath = Join-Path $artifactRoot "$Tool-$safePath-c$Connections.txt"
$commandLine = $Tool + ' ' + (($arguments | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }) -join ' ')
Write-Host $commandLine
$commandLine | Set-Content -LiteralPath (Join-Path $artifactRoot "$Tool-$safePath-c$Connections.command.txt")

& $Tool @arguments 2>&1 | Tee-Object -FilePath $outputPath
exit $LASTEXITCODE
