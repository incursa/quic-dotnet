[CmdletBinding()]
param(
    [string]$BaseUrl = 'https://localhost:4433',
    [string]$CurlPath = 'curl',
    [switch]$Insecure
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$paths = @(
    '/',
    '/api/status',
    '/api/headers',
    '/plaintext',
    '/json'
)

$failed = $false
$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('incursa-h3-smoke-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempRoot | Out-Null

try {
    foreach ($path in $paths) {
        $url = $BaseUrl.TrimEnd('/') + $path
        $bodyPath = Join-Path $tempRoot (($path.Trim('/').Replace('/', '_')) + '.body')
        if ($path -eq '/') {
            $bodyPath = Join-Path $tempRoot 'root.body'
        }

        $arguments = @(
            '--http3-only',
            '--silent',
            '--show-error',
            '--location',
            '--output', $bodyPath,
            '--write-out', "status=%{http_code}`nprotocol=%{http_version}`ncontent_type=%{content_type}`n",
            $url
        )
        if ($Insecure) {
            $arguments = @('--insecure') + $arguments
        }

        Write-Host "==> $url"
        $metadata = & $CurlPath @arguments 2>&1
        $exitCode = $LASTEXITCODE
        $metadataText = ($metadata | Out-String).Trim()
        Write-Host $metadataText

        $status = if ($metadataText -match 'status=(\d+)') { [int]$Matches[1] } else { 0 }
        if ($exitCode -ne 0 -or $status -lt 200 -or $status -ge 300) {
            $failed = $true
            Write-Warning "Smoke request failed for $url with exitCode=$exitCode status=$status"
        }

        if (Test-Path -LiteralPath $bodyPath) {
            $bytes = [System.IO.File]::ReadAllBytes($bodyPath)
            $count = [Math]::Min(200, $bytes.Length)
            $preview = [System.Text.Encoding]::UTF8.GetString($bytes, 0, $count)
            Write-Host 'first_200_bytes:'
            Write-Host $preview
        }
    }
}
finally {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}

if ($failed) {
    exit 1
}
