$ErrorActionPreference = "Stop"

if ($IsWindows) {
    & "$PSScriptRoot/run-windows.ps1" @args
    exit $LASTEXITCODE
}

if ($IsLinux) {
    & bash "$PSScriptRoot/run-linux.sh" @args
    exit $LASTEXITCODE
}

throw "Unsupported OS for quic-dotnet ProtocolLab package."
