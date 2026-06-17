[CmdletBinding()]
param(
    [string] $ProtocolLabRoot = "C:\shared\src\incursa\protocol-lab",

    [string] $ProtocolLabExecutionRoot,

    [string[]] $Suite = @("h3-local-v1-comparison"),

    [ValidateSet("Quick", "Regression", "Comparison")]
    [string] $WorkflowProfile = "Quick",

    [string] $RunIdPrefix = "local-quic-dev-$((Get-Date).ToString('yyyyMMddHHmmss'))",

    [ValidateSet("Debug", "Release")]
    [string] $Configuration = "Release",

    [ValidateSet("Debug", "Release")]
    [string] $TargetConfiguration,

    [ValidateSet("process", "docker", "external")]
    [string] $TargetMode,

    [ValidateSet("published-port", "shared-docker-network")]
    [string] $TargetNetworkMode,

    [string] $ExecutionProfile,

    [int] $DurationSeconds,

    [int] $WarmupSeconds,

    [int] $Repetitions,

    [int] $Connections,

    [int] $StreamsPerConnection,

    [string] $BaseUrl,

    [string] $Output = ".artifacts\runs",

    [string] $PublicationOutputRoot = ".artifacts\publication",

    [string] $PackageVersion,

    [switch] $UseProjectReferences,

    [switch] $UseLocalPackages,

    [switch] $NoRestore,

    [Alias("Implementation")]
    [string[]] $Implementations,

    [Alias("Scenario")]
    [string[]] $Scenarios,

    [string] $LocalFeedRoot,

    [string] $LocalPackageCacheRoot,

    [string] $LocalNuGetConfigPath,

    [switch] $RunBuild,

    [switch] $RunTests,

    [switch] $RunCheck,

    [switch] $PrepareOnly,

    [switch] $UploadAfterRun,

    [string] $R2CredentialsPath,

    [string] $R2CredentialsPathEnvironmentVariable = "PROTOCOL_LAB_R2_CREDENTIALS_PATH",

    [string] $R2SecretVault,

    [string] $R2AccessKeyIdSecretName = "ProtocolLab-R2-AccessKeyId",

    [string] $R2SecretAccessKeySecretName = "ProtocolLab-R2-SecretAccessKey",

    [string] $CloudflareAccountIdSecretName = "ProtocolLab-CloudflareAccountId",

    [string] $R2EndpointSecretName = "ProtocolLab-R2-Endpoint",

    [string] $R2SessionTokenSecretName = "ProtocolLab-R2-SessionToken",

    [string] $BucketName = "protocol-lab-reports",

    [ValidateRange(1, 64)]
    [int] $UploadConcurrency = 8,

    [switch] $NoUploadVerification,

    [switch] $RequirePublishableUpload,

    [switch] $FailOnError,

    [switch] $DryRun,

    [string] $DotNetPath = "dotnet",

    [string] $PowerShellPath = "pwsh",

    [string] $PythonPath = "python"
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

function Assert-PathUnderRoot {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,

        [Parameter(Mandatory = $true)]
        [string] $Root
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $fullRoot = [System.IO.Path]::GetFullPath($Root).TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
    $rootPrefix = $fullRoot + [System.IO.Path]::DirectorySeparatorChar

    if (-not $fullPath.Equals($fullRoot, [StringComparison]::OrdinalIgnoreCase) -and
        -not $fullPath.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Path '$fullPath' is outside expected root '$fullRoot'."
    }
}

function Resolve-ProtocolLabExecutionRoot {
    param(
        [Parameter(Mandatory = $true)]
        [string] $ContractRoot,

        [string] $RequestedExecutionRoot,

        [Parameter(Mandatory = $true)]
        [string] $BasePath
    )

    $candidates = New-Object System.Collections.Generic.List[string]

    if (-not [string]::IsNullOrWhiteSpace($RequestedExecutionRoot)) {
        $candidates.Add((Resolve-FullPath -Path $RequestedExecutionRoot -BasePath $BasePath)) | Out-Null
    }

    $environmentRoot = [Environment]::GetEnvironmentVariable("PROTOCOL_LAB_EXECUTION_ROOT")
    if (-not [string]::IsNullOrWhiteSpace($environmentRoot)) {
        $candidates.Add((Resolve-FullPath -Path $environmentRoot -BasePath $BasePath)) | Out-Null
    }

    $candidates.Add($ContractRoot) | Out-Null

    $siblingInternalRoot = Join-Path (Split-Path -Parent $ContractRoot) "protocol-lab-internal"
    $candidates.Add($siblingInternalRoot) | Out-Null

    $checked = New-Object System.Collections.Generic.List[string]
    foreach ($candidate in $candidates) {
        if ([string]::IsNullOrWhiteSpace($candidate)) {
            continue
        }

        $resolvedCandidate = [System.IO.Path]::GetFullPath($candidate)
        if ($checked.Contains($resolvedCandidate)) {
            continue
        }

        $checked.Add($resolvedCandidate) | Out-Null
        $benchmarkScript = Join-Path $resolvedCandidate "scripts\benchmarking\Invoke-ProtocolLabBenchmarkSet.ps1"
        $solutionPath = Join-Path $resolvedCandidate "Incursa.ProtocolLab.sln"
        if ((Test-Path -LiteralPath $benchmarkScript -PathType Leaf) -and
            (Test-Path -LiteralPath $solutionPath -PathType Leaf)) {
            return $resolvedCandidate
        }
    }

    throw "ProtocolLab benchmark execution root was not found. Checked: $($checked -join ', '). Expected scripts\benchmarking\Invoke-ProtocolLabBenchmarkSet.ps1 and Incursa.ProtocolLab.sln. Keep public contracts in -ProtocolLabRoot and pass -ProtocolLabExecutionRoot for the runnable internal checkout."
}

function Format-CommandLine {
    param(
        [Parameter(Mandatory = $true)]
        [string] $FileName,

        [Parameter(Mandatory = $true)]
        [string[]] $Arguments
    )

    $escaped = foreach ($argument in $Arguments) {
        if ($argument -match '[\s"]') {
            '"' + ($argument -replace '"', '\"') + '"'
        }
        else {
            $argument
        }
    }

    "$FileName $($escaped -join ' ')"
}

function Format-PowerShellArgument {
    param([Parameter(Mandatory = $true)][string] $Value)

    if ($Value -match '^-[A-Za-z][A-Za-z0-9-]*$') {
        return $Value
    }

    return "'" + ($Value -replace "'", "''") + "'"
}

function Format-PowerShellScriptInvocation {
    param(
        [Parameter(Mandatory = $true)]
        [string] $ScriptPath,

        [Parameter(Mandatory = $true)]
        [string[]] $Arguments
    )

    $tokens = New-Object System.Collections.Generic.List[string]
    $tokens.Add("&") | Out-Null
    $tokens.Add((Format-PowerShellArgument -Value $ScriptPath)) | Out-Null

    foreach ($argument in $Arguments) {
        $tokens.Add((Format-PowerShellArgument -Value $argument)) | Out-Null
    }

    return ($tokens -join " ")
}

function Invoke-LoggedCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string] $FileName,

        [Parameter(Mandatory = $true)]
        [string[]] $Arguments,

        [string] $WorkingDirectory
    )

    Write-Host ""
    if (-not [string]::IsNullOrWhiteSpace($WorkingDirectory)) {
        Write-Host "Working directory: $WorkingDirectory" -ForegroundColor DarkGray
    }

    Write-Host (Format-CommandLine $FileName $Arguments) -ForegroundColor Yellow

    if ($DryRun) {
        return
    }

    if ([string]::IsNullOrWhiteSpace($WorkingDirectory)) {
        & $FileName @Arguments
    }
    else {
        Push-Location $WorkingDirectory
        try {
            & $FileName @Arguments
        }
        finally {
            Pop-Location
        }
    }

    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code $LASTEXITCODE."
    }
}

function Invoke-LoggedCommandForExitCode {
    param(
        [Parameter(Mandatory = $true)]
        [string] $FileName,

        [Parameter(Mandatory = $true)]
        [string[]] $Arguments,

        [string] $WorkingDirectory
    )

    Write-Host ""
    if (-not [string]::IsNullOrWhiteSpace($WorkingDirectory)) {
        Write-Host "Working directory: $WorkingDirectory" -ForegroundColor DarkGray
    }

    Write-Host (Format-CommandLine $FileName $Arguments) -ForegroundColor Yellow

    if ($DryRun) {
        return 0
    }

    if ([string]::IsNullOrWhiteSpace($WorkingDirectory)) {
        & $FileName @Arguments
    }
    else {
        Push-Location $WorkingDirectory
        try {
            & $FileName @Arguments
        }
        finally {
            Pop-Location
        }
    }

    return $LASTEXITCODE
}

function Invoke-LoggedPowerShellScript {
    param(
        [Parameter(Mandatory = $true)]
        [string] $PowerShellDisplayName,

        [Parameter(Mandatory = $true)]
        [string] $ScriptPath,

        [Parameter(Mandatory = $true)]
        [string[]] $Arguments,

        [string] $WorkingDirectory
    )

    Write-Host ""
    if (-not [string]::IsNullOrWhiteSpace($WorkingDirectory)) {
        Write-Host "Working directory: $WorkingDirectory" -ForegroundColor DarkGray
    }

    $displayArguments = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $ScriptPath) + $Arguments
    Write-Host (Format-CommandLine $PowerShellDisplayName $displayArguments) -ForegroundColor Yellow

    if ($DryRun) {
        return
    }

    $invocation = Format-PowerShellScriptInvocation -ScriptPath $ScriptPath -Arguments $Arguments

    if ([string]::IsNullOrWhiteSpace($WorkingDirectory)) {
        Invoke-Expression $invocation | Out-Host
        return
    }

    Push-Location $WorkingDirectory
    try {
        Invoke-Expression $invocation | Out-Host
    }
    finally {
        Pop-Location
    }
}

function Invoke-LoggedPowerShellScriptForExitCode {
    param(
        [Parameter(Mandatory = $true)]
        [string] $PowerShellDisplayName,

        [Parameter(Mandatory = $true)]
        [string] $ScriptPath,

        [Parameter(Mandatory = $true)]
        [string[]] $Arguments,

        [string] $WorkingDirectory
    )

    try {
        Invoke-LoggedPowerShellScript -PowerShellDisplayName $PowerShellDisplayName -ScriptPath $ScriptPath -Arguments $Arguments -WorkingDirectory $WorkingDirectory
        return 0
    }
    catch {
        Write-Warning $_.Exception.Message
        return 1
    }
}

function Get-ProtocolLabPackageVersion {
    param([Parameter(Mandatory = $true)][string] $ProtocolLabDirectory)

    $packagesPath = Join-Path $ProtocolLabDirectory "Directory.Packages.props"
    if (-not (Test-Path -LiteralPath $packagesPath)) {
        throw "ProtocolLab Directory.Packages.props was not found: $packagesPath"
    }

    [xml] $packages = Get-Content -LiteralPath $packagesPath -Raw
    $versionNode = $packages.Project.ItemGroup.PackageVersion |
        Where-Object { $_.Include -eq "Incursa.Quic" } |
        Select-Object -First 1

    if ($null -eq $versionNode -or [string]::IsNullOrWhiteSpace($versionNode.Version)) {
        throw "Could not determine ProtocolLab's Incursa.Quic package version from $packagesPath."
    }

    return [string] $versionNode.Version
}

function Get-NormalizedSuites {
    param([string[]] $SuiteValues)

    $normalized = New-Object System.Collections.Generic.List[string]
    foreach ($suiteValue in @($SuiteValues)) {
        foreach ($suiteName in @($suiteValue -split ",")) {
            $trimmed = $suiteName.Trim()
            if (-not [string]::IsNullOrWhiteSpace($trimmed)) {
                $normalized.Add($trimmed) | Out-Null
            }
        }
    }

    if ($normalized.Count -eq 0) {
        throw "Specify at least one ProtocolLab suite with -Suite."
    }

    return $normalized.ToArray()
}

function Join-FilterValues {
    param([AllowNull()][string[]] $Values)

    $normalized = New-Object System.Collections.Generic.List[string]
    foreach ($value in @($Values)) {
        foreach ($entry in @($value -split ",")) {
            $trimmed = $entry.Trim()
            if (-not [string]::IsNullOrWhiteSpace($trimmed)) {
                $normalized.Add($trimmed) | Out-Null
            }
        }
    }

    return ($normalized -join ",")
}

function Get-EnvironmentValue {
    param([Parameter(Mandatory = $true)][string] $Name)

    return [Environment]::GetEnvironmentVariable($Name)
}

function Test-R2UploadEnvironment {
    $hasAccessKey = -not [string]::IsNullOrWhiteSpace((Get-EnvironmentValue -Name "AWS_ACCESS_KEY_ID"))
    $hasSecretKey = -not [string]::IsNullOrWhiteSpace((Get-EnvironmentValue -Name "AWS_SECRET_ACCESS_KEY"))
    $hasEndpoint = -not [string]::IsNullOrWhiteSpace((Get-EnvironmentValue -Name "R2_ENDPOINT"))
    $hasAccountId = -not [string]::IsNullOrWhiteSpace((Get-EnvironmentValue -Name "CLOUDFLARE_ACCOUNT_ID"))

    return $hasAccessKey -and $hasSecretKey -and ($hasEndpoint -or $hasAccountId)
}

function Set-DefaultR2Region {
    if ([string]::IsNullOrWhiteSpace((Get-EnvironmentValue -Name "AWS_DEFAULT_REGION"))) {
        [Environment]::SetEnvironmentVariable("AWS_DEFAULT_REGION", "auto")
    }
}

function ConvertTo-SecretText {
    param($Value)

    if ($null -eq $Value) {
        return $null
    }

    if ($Value -is [System.Security.SecureString]) {
        $credential = [pscredential]::new("secret", $Value)
        return $credential.GetNetworkCredential().Password
    }

    return [string] $Value
}

function Get-SecretManagementValue {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Name,

        [string] $VaultName
    )

    $getSecret = Get-Command -Name Get-Secret -ErrorAction SilentlyContinue
    if ($null -eq $getSecret) {
        return $null
    }

    $arguments = @{
        Name = $Name
        ErrorAction = "SilentlyContinue"
    }

    if (-not [string]::IsNullOrWhiteSpace($VaultName)) {
        $arguments["Vault"] = $VaultName
    }

    try {
        if ($getSecret.Parameters.ContainsKey("AsPlainText")) {
            $arguments["AsPlainText"] = $true
        }

        return ConvertTo-SecretText -Value (Get-Secret @arguments)
    }
    catch {
        return $null
    }
}

function Set-R2EnvironmentValue {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Name,

        [string] $Value
    )

    if (-not [string]::IsNullOrWhiteSpace($Value)) {
        [Environment]::SetEnvironmentVariable($Name, $Value)
    }
}

function Set-R2EnvironmentFromValues {
    param(
        [hashtable] $Values
    )

    if ($Values.ContainsKey("R2_ACCESS_KEY_ID") -and -not [string]::IsNullOrWhiteSpace($Values["R2_ACCESS_KEY_ID"])) {
        Set-R2EnvironmentValue -Name "AWS_ACCESS_KEY_ID" -Value $Values["R2_ACCESS_KEY_ID"]
    }
    elseif ($Values.ContainsKey("AWS_ACCESS_KEY_ID")) {
        Set-R2EnvironmentValue -Name "AWS_ACCESS_KEY_ID" -Value $Values["AWS_ACCESS_KEY_ID"]
    }

    if ($Values.ContainsKey("R2_SECRET_ACCESS_KEY") -and -not [string]::IsNullOrWhiteSpace($Values["R2_SECRET_ACCESS_KEY"])) {
        Set-R2EnvironmentValue -Name "AWS_SECRET_ACCESS_KEY" -Value $Values["R2_SECRET_ACCESS_KEY"]
    }
    elseif ($Values.ContainsKey("AWS_SECRET_ACCESS_KEY")) {
        Set-R2EnvironmentValue -Name "AWS_SECRET_ACCESS_KEY" -Value $Values["AWS_SECRET_ACCESS_KEY"]
    }

    if ($Values.ContainsKey("AWS_SESSION_TOKEN")) {
        Set-R2EnvironmentValue -Name "AWS_SESSION_TOKEN" -Value $Values["AWS_SESSION_TOKEN"]
    }
    elseif ($Values.ContainsKey("R2_SESSION_TOKEN")) {
        Set-R2EnvironmentValue -Name "AWS_SESSION_TOKEN" -Value $Values["R2_SESSION_TOKEN"]
    }

    if ($Values.ContainsKey("CLOUDFLARE_ACCOUNT_ID")) {
        Set-R2EnvironmentValue -Name "CLOUDFLARE_ACCOUNT_ID" -Value $Values["CLOUDFLARE_ACCOUNT_ID"]
    }

    if ($Values.ContainsKey("R2_ENDPOINT")) {
        Set-R2EnvironmentValue -Name "R2_ENDPOINT" -Value $Values["R2_ENDPOINT"]
    }

    Set-DefaultR2Region
}

function Assert-R2UploadEnvironment {
    if (-not (Test-R2UploadEnvironment)) {
        throw "R2 upload credentials are incomplete. Set AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and either CLOUDFLARE_ACCOUNT_ID or R2_ENDPOINT; or provide a credentials file with -R2CredentialsPath / $R2CredentialsPathEnvironmentVariable; or store them with PowerShell SecretManagement."
    }
}

function Set-R2EnvironmentFromFile {
    param([Parameter(Mandatory = $true)][string] $Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "R2 credentials file was not found: $Path"
    }

    $values = @{}
    foreach ($line in Get-Content -LiteralPath $Path) {
        $trimmed = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.StartsWith("#")) {
            continue
        }

        if ($trimmed -match '^([^=:\s]+)\s*[=:]\s*(.+)$') {
            $values[$matches[1]] = $matches[2].Trim().Trim('"')
        }
    }

    Set-R2EnvironmentFromValues -Values $values
    Assert-R2UploadEnvironment
}

function Set-R2EnvironmentFromSecretManagement {
    $values = @{}

    $secretMappings = @(
        @{ SecretName = $R2AccessKeyIdSecretName; EnvironmentName = "AWS_ACCESS_KEY_ID" },
        @{ SecretName = $R2SecretAccessKeySecretName; EnvironmentName = "AWS_SECRET_ACCESS_KEY" },
        @{ SecretName = $CloudflareAccountIdSecretName; EnvironmentName = "CLOUDFLARE_ACCOUNT_ID" },
        @{ SecretName = $R2EndpointSecretName; EnvironmentName = "R2_ENDPOINT" },
        @{ SecretName = $R2SessionTokenSecretName; EnvironmentName = "AWS_SESSION_TOKEN" }
    )

    foreach ($mapping in $secretMappings) {
        if ([string]::IsNullOrWhiteSpace($mapping.SecretName)) {
            continue
        }

        $secretValue = Get-SecretManagementValue -Name $mapping.SecretName -VaultName $R2SecretVault
        if (-not [string]::IsNullOrWhiteSpace($secretValue)) {
            $values[$mapping.EnvironmentName] = $secretValue
        }
    }

    if ($values.Count -eq 0) {
        return $false
    }

    Set-R2EnvironmentFromValues -Values $values
    return (Test-R2UploadEnvironment)
}

function Initialize-R2UploadEnvironment {
    if (Test-R2UploadEnvironment) {
        Set-DefaultR2Region
        Write-Host "  R2 credentials: environment variables" -ForegroundColor DarkGray
        return
    }

    $credentialPath = $null
    if (-not [string]::IsNullOrWhiteSpace($R2CredentialsPath)) {
        $credentialPath = $R2CredentialsPath
    }
    elseif (-not [string]::IsNullOrWhiteSpace($R2CredentialsPathEnvironmentVariable)) {
        $credentialPath = Get-EnvironmentValue -Name $R2CredentialsPathEnvironmentVariable
    }

    if (-not [string]::IsNullOrWhiteSpace($credentialPath)) {
        $resolvedCredentialPath = Resolve-FullPath -Path $credentialPath -BasePath $repoRoot
        Set-R2EnvironmentFromFile -Path $resolvedCredentialPath
        Write-Host "  R2 credentials: $resolvedCredentialPath" -ForegroundColor DarkGray
        return
    }

    if (Set-R2EnvironmentFromSecretManagement) {
        Set-DefaultR2Region
        Write-Host "  R2 credentials: PowerShell SecretManagement" -ForegroundColor DarkGray
        return
    }

    Assert-R2UploadEnvironment
}

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\.."))
$resolvedProtocolLabRoot = Resolve-FullPath -Path $ProtocolLabRoot -BasePath $repoRoot

if (-not (Test-Path -LiteralPath $resolvedProtocolLabRoot)) {
    throw "ProtocolLab root was not found: $resolvedProtocolLabRoot"
}

$resolvedProtocolLabExecutionRoot = Resolve-ProtocolLabExecutionRoot -ContractRoot $resolvedProtocolLabRoot -RequestedExecutionRoot $ProtocolLabExecutionRoot -BasePath $repoRoot
$benchmarkScript = Join-Path $resolvedProtocolLabExecutionRoot "scripts\benchmarking\Invoke-ProtocolLabBenchmarkSet.ps1"
if (-not (Test-Path -LiteralPath $benchmarkScript)) {
    throw "ProtocolLab benchmark set script was not found in execution root: $benchmarkScript"
}

if ($UseProjectReferences -and $UseLocalPackages) {
    throw "Specify either -UseProjectReferences or -UseLocalPackages, not both."
}

$useProjectReferenceMode = [bool]$UseProjectReferences
$useLocalPackageMode = -not $useProjectReferenceMode
$protocolLabArtifactsRoot = Join-Path $resolvedProtocolLabExecutionRoot ".artifacts"
$resolvedFeedRoot = $null
$resolvedPackageCacheRoot = $null
$resolvedNuGetConfigPath = $null

if ($useLocalPackageMode) {
    if ([string]::IsNullOrWhiteSpace($PackageVersion)) {
        $PackageVersion = Get-ProtocolLabPackageVersion -ProtocolLabDirectory $resolvedProtocolLabExecutionRoot
    }

    $resolvedFeedRoot = if ([string]::IsNullOrWhiteSpace($LocalFeedRoot)) {
        Join-Path $protocolLabArtifactsRoot "local-quic-feed"
    }
    else {
        Resolve-FullPath -Path $LocalFeedRoot -BasePath $resolvedProtocolLabExecutionRoot
    }

    $resolvedPackageCacheRoot = if ([string]::IsNullOrWhiteSpace($LocalPackageCacheRoot)) {
        Join-Path $protocolLabArtifactsRoot "nuget-packages-local-quic"
    }
    else {
        Resolve-FullPath -Path $LocalPackageCacheRoot -BasePath $resolvedProtocolLabExecutionRoot
    }

    $resolvedNuGetConfigPath = if ([string]::IsNullOrWhiteSpace($LocalNuGetConfigPath)) {
        Join-Path $protocolLabArtifactsRoot "local-quic.NuGet.config"
    }
    else {
        Resolve-FullPath -Path $LocalNuGetConfigPath -BasePath $resolvedProtocolLabExecutionRoot
    }

    Assert-PathUnderRoot -Path $resolvedFeedRoot -Root $protocolLabArtifactsRoot
    Assert-PathUnderRoot -Path $resolvedPackageCacheRoot -Root $protocolLabArtifactsRoot
    Assert-PathUnderRoot -Path $resolvedNuGetConfigPath -Root $protocolLabArtifactsRoot
}

$selectedSuites = @(Get-NormalizedSuites -SuiteValues $Suite)
$implementationFilter = if ($PSBoundParameters.ContainsKey("Implementations")) { Join-FilterValues -Values $Implementations } else { $null }
$scenarioFilter = if ($PSBoundParameters.ContainsKey("Scenarios")) { Join-FilterValues -Values $Scenarios } else { $null }
$packageProjects = @(
    "src\Incursa.Qpack\Incursa.Qpack.csproj",
    "src\Incursa.Quic\Incursa.Quic.csproj",
    "src\Incursa.Quic.Http3\Incursa.Quic.Http3.csproj"
)

foreach ($packageProject in $packageProjects) {
    $fullProjectPath = Join-Path $repoRoot $packageProject
    if (-not (Test-Path -LiteralPath $fullProjectPath)) {
        throw "Package project was not found: $fullProjectPath"
    }
}

Write-Host "ProtocolLab local Incursa.Quic benchmark loop" -ForegroundColor Cyan
Write-Host "  quic-dotnet: $repoRoot"
Write-Host "  protocol-lab contracts: $resolvedProtocolLabRoot"
Write-Host "  protocol-lab execution: $resolvedProtocolLabExecutionRoot"
Write-Host "  dependency mode: $(if ($useProjectReferenceMode) { 'project references' } else { 'local packages' })"
if ($useLocalPackageMode) {
    Write-Host "  package version: $PackageVersion"
}
Write-Host "  suite: $($selectedSuites -join ',')"
if (-not [string]::IsNullOrWhiteSpace($implementationFilter)) {
    Write-Host "  implementation filter: $implementationFilter"
}
if (-not [string]::IsNullOrWhiteSpace($scenarioFilter)) {
    Write-Host "  scenario filter: $scenarioFilter"
}
Write-Host "  workflow profile: $WorkflowProfile"
Write-Host "  run id prefix: $RunIdPrefix"
if ($useLocalPackageMode) {
    Write-Host "  local feed: $resolvedFeedRoot"
    Write-Host "  local package cache: $resolvedPackageCacheRoot"
    Write-Host "  local NuGet config: $resolvedNuGetConfigPath"
}
Write-Host "  upload after run: $([bool]$UploadAfterRun)"

if ($useLocalPackageMode -and -not $DryRun) {
    New-Item -ItemType Directory -Force -Path $resolvedFeedRoot, $resolvedPackageCacheRoot, (Split-Path -Parent $resolvedNuGetConfigPath) | Out-Null

    Get-ChildItem -LiteralPath $resolvedFeedRoot -Filter "*.nupkg" -File -ErrorAction SilentlyContinue |
        Remove-Item -Force

    foreach ($packageDirectory in @("incursa.qpack", "incursa.quic", "incursa.quic.http3")) {
        $cachePath = Join-Path $resolvedPackageCacheRoot $packageDirectory
        if (Test-Path -LiteralPath $cachePath) {
            Assert-PathUnderRoot -Path $cachePath -Root $resolvedPackageCacheRoot
            Remove-Item -LiteralPath $cachePath -Recurse -Force
        }
    }
}

if ($useLocalPackageMode) {
    foreach ($packageProject in $packageProjects) {
        $packArgs = @(
            "pack",
            (Join-Path $repoRoot $packageProject),
            "-c",
            $Configuration,
            "-o",
            $resolvedFeedRoot,
            "/p:Version=$PackageVersion"
        )

        Invoke-LoggedCommand -FileName $DotNetPath -Arguments $packArgs -WorkingDirectory $repoRoot
    }

    $nugetConfig = @"
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="local-quic" value="$resolvedFeedRoot" />
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
  </packageSources>
  <packageSourceMapping>
    <packageSource key="local-quic">
      <package pattern="Incursa.Qpack" />
      <package pattern="Incursa.Quic" />
      <package pattern="Incursa.Quic.Http3" />
    </packageSource>
    <packageSource key="nuget.org">
      <package pattern="*" />
    </packageSource>
  </packageSourceMapping>
</configuration>
"@

    if ($DryRun) {
        Write-Host ""
        Write-Host "Would write local NuGet config:" -ForegroundColor Yellow
        Write-Host $resolvedNuGetConfigPath
    }
    else {
        Set-Content -LiteralPath $resolvedNuGetConfigPath -Value $nugetConfig -Encoding utf8
    }
}

$restoreArgs = @("restore", (Join-Path $resolvedProtocolLabExecutionRoot "Incursa.ProtocolLab.sln"))
if ($useLocalPackageMode) {
    $restoreArgs += @(
        "--configfile",
        $resolvedNuGetConfigPath,
        "--force",
        "--no-cache"
    )
}
else {
    $restoreArgs += "/p:IncursaQuicSourceRoot=$repoRoot"
}

$previousRestoreConfigFile = [Environment]::GetEnvironmentVariable("RestoreConfigFile")
$previousNuGetPackages = [Environment]::GetEnvironmentVariable("NUGET_PACKAGES")

try {
    if ($useLocalPackageMode -and -not $DryRun) {
        [Environment]::SetEnvironmentVariable("RestoreConfigFile", $resolvedNuGetConfigPath)
        [Environment]::SetEnvironmentVariable("NUGET_PACKAGES", $resolvedPackageCacheRoot)
    }

    if (-not $NoRestore) {
        Invoke-LoggedCommand -FileName $DotNetPath -Arguments $restoreArgs -WorkingDirectory $resolvedProtocolLabExecutionRoot
    }
    else {
        Write-Host ""
        Write-Host "Skipping ProtocolLab restore because -NoRestore was set." -ForegroundColor Yellow
    }

    if ($PrepareOnly) {
        Write-Host ""
        if ($NoRestore) {
            Write-Host "PrepareOnly completed without restore because -NoRestore was set. Skipping benchmark." -ForegroundColor Cyan
        }
        else {
            Write-Host "Prepared ProtocolLab dependencies. Skipping benchmark because -PrepareOnly was set." -ForegroundColor Cyan
        }
        return
    }

    $benchmarkArgs = @(
        "-Suite",
        ($selectedSuites -join ","),
        "-WorkflowProfile",
        $WorkflowProfile,
        "-RunIdPrefix",
        $RunIdPrefix,
        "-Output",
        $Output,
        "-PublicationOutputRoot",
        $PublicationOutputRoot,
        "-Configuration",
        $Configuration
    )

    if ($useProjectReferenceMode) {
        $benchmarkArgs += @("-IncursaQuicSourceRoot", $repoRoot)
    }

    if ($NoRestore) {
        $benchmarkArgs += "-NoRestore"
    }

    if (-not [string]::IsNullOrWhiteSpace($implementationFilter)) {
        $benchmarkArgs += @("-Implementations", $implementationFilter)
    }

    if (-not [string]::IsNullOrWhiteSpace($scenarioFilter)) {
        $benchmarkArgs += @("-Scenarios", $scenarioFilter)
    }

    if ($RunBuild) {
        $benchmarkArgs += "-RunBuild"
    }

    if ($RunTests) {
        $benchmarkArgs += "-RunTests"
    }

    if ($RunCheck) {
        $benchmarkArgs += "-RunCheck"
    }

    if ($PSBoundParameters.ContainsKey("TargetConfiguration") -and -not [string]::IsNullOrWhiteSpace($TargetConfiguration)) {
        $benchmarkArgs += @("-TargetConfiguration", $TargetConfiguration)
    }

    if ($PSBoundParameters.ContainsKey("TargetMode") -and -not [string]::IsNullOrWhiteSpace($TargetMode)) {
        $benchmarkArgs += @("-TargetMode", $TargetMode)
    }

    if ($PSBoundParameters.ContainsKey("TargetNetworkMode") -and -not [string]::IsNullOrWhiteSpace($TargetNetworkMode)) {
        $benchmarkArgs += @("-TargetNetworkMode", $TargetNetworkMode)
    }

    if ($PSBoundParameters.ContainsKey("ExecutionProfile") -and -not [string]::IsNullOrWhiteSpace($ExecutionProfile)) {
        $benchmarkArgs += @("-ExecutionProfile", $ExecutionProfile)
    }

    if ($PSBoundParameters.ContainsKey("DurationSeconds")) {
        $benchmarkArgs += @("-DurationSeconds", $DurationSeconds.ToString([Globalization.CultureInfo]::InvariantCulture))
    }

    if ($PSBoundParameters.ContainsKey("WarmupSeconds")) {
        $benchmarkArgs += @("-WarmupSeconds", $WarmupSeconds.ToString([Globalization.CultureInfo]::InvariantCulture))
    }

    if ($PSBoundParameters.ContainsKey("Repetitions")) {
        $benchmarkArgs += @("-Repetitions", $Repetitions.ToString([Globalization.CultureInfo]::InvariantCulture))
    }

    if ($PSBoundParameters.ContainsKey("Connections")) {
        $benchmarkArgs += @("-Connections", $Connections.ToString([Globalization.CultureInfo]::InvariantCulture))
    }

    if ($PSBoundParameters.ContainsKey("StreamsPerConnection")) {
        $benchmarkArgs += @("-StreamsPerConnection", $StreamsPerConnection.ToString([Globalization.CultureInfo]::InvariantCulture))
    }

    if ($PSBoundParameters.ContainsKey("BaseUrl") -and -not [string]::IsNullOrWhiteSpace($BaseUrl)) {
        $benchmarkArgs += @("-BaseUrl", $BaseUrl)
    }

    if ($FailOnError) {
        $benchmarkArgs += "-FailOnError"
    }

    if ($DryRun) {
        $benchmarkArgs += "-DryRun"
    }

    $benchmarkExitCode = Invoke-LoggedPowerShellScriptForExitCode -PowerShellDisplayName $PowerShellPath -ScriptPath $benchmarkScript -Arguments $benchmarkArgs -WorkingDirectory $resolvedProtocolLabExecutionRoot
    if ($benchmarkExitCode -ne 0) {
        Write-Warning "ProtocolLab benchmark command exited with code $benchmarkExitCode."
        if (-not $UploadAfterRun) {
            throw "Command failed with exit code $benchmarkExitCode."
        }
    }

    if ($UploadAfterRun) {
        $uploadScript = Join-Path $resolvedProtocolLabExecutionRoot "scripts\publication\Upload-ProtocolLabReportBundle.ps1"
        if (-not (Test-Path -LiteralPath $uploadScript)) {
            throw "ProtocolLab R2 upload script was not found: $uploadScript"
        }

        if ($selectedSuites.Count -ne 1) {
            throw "UploadAfterRun currently requires exactly one suite so the publication bundle is unambiguous. Selected suites: $($selectedSuites -join ',')"
        }

        $runId = "$RunIdPrefix-$($selectedSuites[0])"
        $bundleRoot = Resolve-FullPath -Path (Join-Path $PublicationOutputRoot $runId) -BasePath $resolvedProtocolLabExecutionRoot
        if (-not $DryRun -and -not (Test-Path -LiteralPath $bundleRoot)) {
            throw "Publication bundle was not found after the run: $bundleRoot"
        }

        if (-not $DryRun) {
            Initialize-R2UploadEnvironment
        }

        $uploadArgs = @(
            "-BundleRoot",
            $bundleRoot,
            "-BucketName",
            $BucketName,
            "-UploadConcurrency",
            $UploadConcurrency.ToString([Globalization.CultureInfo]::InvariantCulture),
            "-PythonPath",
            $PythonPath
        )

        if (-not $RequirePublishableUpload) {
            $uploadArgs += "-AllowDiagnosticPublication"
        }

        if (-not $NoUploadVerification) {
            $uploadArgs += "-VerifyUploadedObjects"
        }

        if ($DryRun) {
            $uploadArgs += "-DryRun"
        }

        Invoke-LoggedPowerShellScript -PowerShellDisplayName $PowerShellPath -ScriptPath $uploadScript -Arguments $uploadArgs -WorkingDirectory $resolvedProtocolLabExecutionRoot

        if ($benchmarkExitCode -ne 0) {
            throw "Benchmark command failed with exit code $benchmarkExitCode after the publication bundle upload completed."
        }
    }
}
finally {
    if ($useLocalPackageMode -and -not $DryRun) {
        [Environment]::SetEnvironmentVariable("RestoreConfigFile", $previousRestoreConfigFile)
        [Environment]::SetEnvironmentVariable("NUGET_PACKAGES", $previousNuGetPackages)
    }
}
