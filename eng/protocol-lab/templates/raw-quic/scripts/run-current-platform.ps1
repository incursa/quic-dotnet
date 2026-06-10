$ErrorActionPreference = "Stop"

function Get-PackageRuntimeIdentifier {
    if ($IsWindows) {
        return "win-x64"
    }

    if ($IsLinux) {
        return "linux-x64"
    }

    throw "Unsupported OS for quic-dotnet raw QUIC ProtocolLab package."
}

function Copy-DirectoryContents {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Source,

        [Parameter(Mandatory = $true)]
        [string] $Destination
    )

    if (-not (Test-Path -LiteralPath $Source -PathType Container)) {
        throw "Raw QUIC server payload was not found for this platform: $Source"
    }

    New-Item -ItemType Directory -Force -Path $Destination | Out-Null
    Get-ChildItem -LiteralPath $Source -Force | Copy-Item -Destination $Destination -Recurse -Force
}

$packageRoot = Split-Path -Parent $PSScriptRoot
$rid = Get-PackageRuntimeIdentifier
$adapterDll = Join-Path $packageRoot "bin/$rid/Incursa.ProtocolLab.Adapters.IncursaRawQuic.dll"
$serverSource = Join-Path $packageRoot "bin/$rid/servers/IncursaRawQuicServer"
$serverReleaseRoot = Join-Path $packageRoot "servers/IncursaRawQuicServer/bin/Release"
$serverTarget = Join-Path $serverReleaseRoot "protocol-lab-package"

if (-not (Test-Path -LiteralPath $adapterDll -PathType Leaf)) {
    throw "Raw QUIC adapter payload was not found for this platform: $adapterDll"
}

Remove-Item -LiteralPath $serverReleaseRoot -Recurse -Force -ErrorAction SilentlyContinue
Copy-DirectoryContents -Source $serverSource -Destination $serverTarget

& dotnet $adapterDll @args
exit $LASTEXITCODE
