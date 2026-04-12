param(
    [string]$Project = "src/Incursa.Quic/Incursa.Quic.csproj",
    [string]$Configuration = "Release",
    [string]$TargetFramework = "net10.0",
    [string]$RuntimeIdentifier = "win-x64",
    [ValidateSet("Auto", "Regular", "Fallback")]
    [string]$Mode = "Auto",
    [string]$WorkDirectory = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "QualityLane.Common.ps1")

Assert-DotNetAvailable

function Get-VisualStudioInstallPath {
    $vsWherePath = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path $vsWherePath)) {
        return $null
    }

    $installationPath = & $vsWherePath -latest -prerelease -products * -property installationPath
    if ([string]::IsNullOrWhiteSpace($installationPath)) {
        return $null
    }

    return $installationPath.Trim()
}

function Get-LatestExistingDirectory {
    param(
        [Parameter(Mandatory)]
        [string]$ParentPath
    )

    if (-not (Test-Path $ParentPath)) {
        return $null
    }

    $directory = Get-ChildItem -Path $ParentPath -Directory -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending |
        Select-Object -First 1

    if ($null -eq $directory) {
        return $null
    }

    return $directory.FullName
}

function Add-UniquePathEntry {
    param(
        [Parameter(Mandatory)]
        [object]$Entries,

        [Parameter(Mandatory)]
        [string]$CandidatePath
    )

    if ([string]::IsNullOrWhiteSpace($CandidatePath) -or -not (Test-Path $CandidatePath)) {
        return
    }

    $resolvedCandidate = (Resolve-Path $CandidatePath).Path
    if ($Entries -notcontains $resolvedCandidate) {
        $Entries.Add($resolvedCandidate)
    }
}

function Get-NupkgIdentity {
    param(
        [Parameter(Mandatory)]
        [string]$PackagePath
    )

    try {
        if (-not ('System.IO.Compression.ZipFile' -as [type])) {
            Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
        }

        $archive = [System.IO.Compression.ZipFile]::OpenRead($PackagePath)
        try {
            $nuspecEntry = $archive.Entries |
                Where-Object { $_.FullName.EndsWith(".nuspec", [System.StringComparison]::OrdinalIgnoreCase) } |
                Select-Object -First 1

            if ($null -eq $nuspecEntry) {
                throw "Unable to locate the package nuspec inside '$PackagePath'."
            }

            $reader = [System.IO.StreamReader]::new($nuspecEntry.Open())
            try {
                [xml]$nuspec = $reader.ReadToEnd()
            } finally {
                $reader.Dispose()
            }

            $metadata = $nuspec.package.metadata
            if ($null -eq $metadata -or [string]::IsNullOrWhiteSpace([string]$metadata.id) -or [string]::IsNullOrWhiteSpace([string]$metadata.version)) {
                throw "The package nuspec inside '$PackagePath' did not contain a valid id/version pair."
            }

            return [pscustomobject]@{
                Id      = [string]$metadata.id
                Version = [string]$metadata.version
            }
        } finally {
            $archive.Dispose()
        }
    } catch {
        throw "Failed to read package identity from '$PackagePath': $($_.Exception.Message)"
    }
}

function New-AotConsumerProject {
    param(
        [Parameter(Mandatory)]
        [string]$ConsumerPath,

        [Parameter(Mandatory)]
        [string]$TargetFramework,

        [Parameter(Mandatory)]
        [string]$PackageId,

        [Parameter(Mandatory)]
        [string]$PackageVersion,

        [Parameter(Mandatory)]
        [string]$PackageSourcePath
    )

    $projectPath = Join-Path $ConsumerPath "AotPublishConsumer.csproj"
    $programPath = Join-Path $ConsumerPath "Program.cs"
    $nugetConfigPath = Join-Path $ConsumerPath "NuGet.Config"

    $escapedPackageId = [System.Security.SecurityElement]::Escape($PackageId)
    $escapedPackageVersion = [System.Security.SecurityElement]::Escape($PackageVersion)
    $escapedPackageSource = [System.Security.SecurityElement]::Escape((Resolve-Path $PackageSourcePath).Path)

    $projectContent = @"
<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>$TargetFramework</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
  </PropertyGroup>

  <ItemGroup>
    <PackageReference Include="$escapedPackageId" Version="$escapedPackageVersion" />
  </ItemGroup>

</Project>
"@

    $programContent = @"
using Incursa.Quic;

Console.WriteLine($"Connection supported: {QuicConnection.IsSupported}");
Console.WriteLine($"Listener supported: {QuicListener.IsSupported}");
"@

    $nugetConfigContent = @"
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="local" value="$escapedPackageSource" />
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" protocolVersion="3" />
  </packageSources>
  <packageSourceMapping>
    <clear />
    <packageSource key="local">
      <package pattern="$escapedPackageId" />
    </packageSource>
    <packageSource key="nuget.org">
      <package pattern="*" />
    </packageSource>
  </packageSourceMapping>
</configuration>
"@

    Set-Content -Path $projectPath -Value $projectContent -Encoding UTF8
    Set-Content -Path $programPath -Value $programContent -Encoding UTF8
    Set-Content -Path $nugetConfigPath -Value $nugetConfigContent -Encoding UTF8

    return [pscustomobject]@{
        ProjectPath     = $projectPath
        AssemblyName    = "AotPublishConsumer"
        NuGetConfigPath  = $nugetConfigPath
        ProgramPath     = $programPath
    }
}

function Get-FallbackNativeAotEnvironment {
    param(
        [Parameter(Mandatory)]
        [string]$VisualStudioInstallPath
    )

    $pathEntries = [System.Collections.Generic.List[string]]::new()
    $libEntries = [System.Collections.Generic.List[string]]::new()
    $includeEntries = [System.Collections.Generic.List[string]]::new()

    $msvcRoot = Get-LatestExistingDirectory -ParentPath (Join-Path $VisualStudioInstallPath "VC\Tools\MSVC")
    if ($null -ne $msvcRoot) {
        Add-UniquePathEntry -Entries $pathEntries -CandidatePath (Join-Path $msvcRoot "bin\Hostx64\x64")
        Add-UniquePathEntry -Entries $libEntries -CandidatePath (Join-Path $msvcRoot "lib\onecore\x64")
        Add-UniquePathEntry -Entries $includeEntries -CandidatePath (Join-Path $msvcRoot "include")
    }

    $scopeCppSdkRoot = Join-Path $VisualStudioInstallPath "SDK\ScopeCppSDK\vc15"
    if (Test-Path $scopeCppSdkRoot) {
        Add-UniquePathEntry -Entries $pathEntries -CandidatePath (Join-Path $scopeCppSdkRoot "VC\bin")
        Add-UniquePathEntry -Entries $pathEntries -CandidatePath (Join-Path $scopeCppSdkRoot "SDK\bin")
        Add-UniquePathEntry -Entries $libEntries -CandidatePath (Join-Path $scopeCppSdkRoot "VC\lib")
        Add-UniquePathEntry -Entries $libEntries -CandidatePath (Join-Path $scopeCppSdkRoot "SDK\lib")
        Add-UniquePathEntry -Entries $includeEntries -CandidatePath (Join-Path $scopeCppSdkRoot "VC\include")
        Add-UniquePathEntry -Entries $includeEntries -CandidatePath (Join-Path $scopeCppSdkRoot "SDK\include\shared")
        Add-UniquePathEntry -Entries $includeEntries -CandidatePath (Join-Path $scopeCppSdkRoot "SDK\include\ucrt")
        Add-UniquePathEntry -Entries $includeEntries -CandidatePath (Join-Path $scopeCppSdkRoot "SDK\include\um")
    }

    $windowsSdkRoot = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10"
    if (Test-Path $windowsSdkRoot) {
        $latestIncludeRoot = Get-LatestExistingDirectory -ParentPath (Join-Path $windowsSdkRoot "Include")
        if ($null -ne $latestIncludeRoot) {
            Add-UniquePathEntry -Entries $includeEntries -CandidatePath (Join-Path $latestIncludeRoot "shared")
            Add-UniquePathEntry -Entries $includeEntries -CandidatePath (Join-Path $latestIncludeRoot "ucrt")
            Add-UniquePathEntry -Entries $includeEntries -CandidatePath (Join-Path $latestIncludeRoot "um")
            Add-UniquePathEntry -Entries $includeEntries -CandidatePath (Join-Path $latestIncludeRoot "winrt")
            Add-UniquePathEntry -Entries $includeEntries -CandidatePath (Join-Path $latestIncludeRoot "cppwinrt")
        }

        $latestLibRoot = Get-LatestExistingDirectory -ParentPath (Join-Path $windowsSdkRoot "Lib")
        if ($null -ne $latestLibRoot) {
            Add-UniquePathEntry -Entries $libEntries -CandidatePath (Join-Path $latestLibRoot "ucrt\x64")
            Add-UniquePathEntry -Entries $libEntries -CandidatePath (Join-Path $latestLibRoot "um\x64")
        }
    }

    if ($pathEntries.Count -eq 0 -or $libEntries.Count -eq 0 -or $includeEntries.Count -eq 0) {
        throw "Unable to assemble a fallback NativeAOT toolchain from '$VisualStudioInstallPath'."
    }

    return [pscustomobject]@{
        Path      = [string]::Join([System.IO.Path]::PathSeparator, $pathEntries)
        Lib       = [string]::Join([System.IO.Path]::PathSeparator, $libEntries)
        Include   = [string]::Join([System.IO.Path]::PathSeparator, $includeEntries)
        VisualStudioInstallPath = $VisualStudioInstallPath
        MsvcRoot = $msvcRoot
        ScopeCppSdkRoot = $scopeCppSdkRoot
        WindowsSdkRoot = $windowsSdkRoot
    }
}

function Clear-ConsumerBuildOutputs {
    param(
        [Parameter(Mandatory)]
        [string]$ConsumerPath
    )

    foreach ($child in @("bin", "obj")) {
        $candidate = Join-Path $ConsumerPath $child
        if (Test-Path $candidate) {
            Remove-Item -Path $candidate -Recurse -Force
        }
    }
}

function Invoke-AotPublish {
    param(
        [Parameter(Mandatory)]
        [string]$ConsumerProjectPath,

        [Parameter(Mandatory)]
        [string]$ConsumerPath,

        [Parameter(Mandatory)]
        [string]$PublishPath,

        [Parameter(Mandatory)]
        [string]$Configuration,

        [Parameter(Mandatory)]
        [string]$RuntimeIdentifier,

        [switch]$UseFallbackEnvironment,

        [object]$FallbackEnvironment
    )

    Clear-ConsumerBuildOutputs -ConsumerPath $ConsumerPath
    Initialize-ArtifactDirectory -Path $PublishPath -Clean | Out-Null

    $publishArgs = @(
        "publish"
        $ConsumerProjectPath
        "--configuration"
        $Configuration
        "-r"
        $RuntimeIdentifier
        "-p:SelfContained=true"
        "-p:PublishAot=true"
        "-p:TreatWarningsAsErrors=true"
        "--output"
        $PublishPath
    )

    if ($UseFallbackEnvironment) {
        if ($null -eq $FallbackEnvironment) {
            throw "Fallback NativeAOT environment details were not provided."
        }

        $env:IlcUseEnvironmentalTools = "true"
        $env:PATH = "$($FallbackEnvironment.Path);$env:PATH"
        $env:LIB = "$($FallbackEnvironment.Lib);$env:LIB"
        $env:INCLUDE = "$($FallbackEnvironment.Include);$env:INCLUDE"
    } else {
        Remove-Item Env:IlcUseEnvironmentalTools -ErrorAction SilentlyContinue
    }

    Write-Host "Running dotnet publish..." -ForegroundColor Cyan
    Write-Host "Project: $ConsumerProjectPath" -ForegroundColor Yellow
    Write-Host "Output:   $PublishPath" -ForegroundColor Yellow
    Write-Host "Mode:     $(if ($UseFallbackEnvironment) { 'fallback' } else { 'regular' })" -ForegroundColor Yellow

    Push-Location $ConsumerPath
    try {
        & dotnet @publishArgs
        if ($LASTEXITCODE -ne 0) {
            throw "dotnet publish failed with exit code $LASTEXITCODE."
        }
    } finally {
        Pop-Location
    }

    $publishedExe = Join-Path $PublishPath "AotPublishConsumer.exe"
    if (-not (Test-Path $publishedExe)) {
        throw "The publish step completed, but '$publishedExe' was not produced."
    }

    Write-Host "Running published executable..." -ForegroundColor Cyan
    & $publishedExe
    if ($LASTEXITCODE -ne 0) {
        throw "The published executable failed with exit code $LASTEXITCODE."
    }

    Write-Host "Executable output verified." -ForegroundColor Green
}

$repoRoot = Get-QualityRepoRoot
$projectPath = Resolve-RepoPath -RepoRoot $repoRoot -Path $Project

if ([string]::IsNullOrWhiteSpace($WorkDirectory)) {
    $workDirectory = Join-Path $env:TEMP "incursa-quic-aot-publish"
} else {
    $workDirectory = Resolve-RepoPath -RepoRoot $repoRoot -Path $WorkDirectory
}

$workRoot = Initialize-ArtifactDirectory -Path $workDirectory -Clean
$packPath = Initialize-ArtifactDirectory -Path (Join-Path $workRoot "pack") -Clean
$consumerPath = Initialize-ArtifactDirectory -Path (Join-Path $workRoot "consumer") -Clean
$regularPublishPath = Join-Path $workRoot "publish-regular"
$fallbackPublishPath = Join-Path $workRoot "publish-fallback"

Write-Host "Preparing NativeAOT publish test..." -ForegroundColor Cyan
Write-Host "Repository project: $projectPath" -ForegroundColor Yellow
Write-Host "Configuration: $Configuration" -ForegroundColor Yellow
Write-Host "Target framework: $TargetFramework" -ForegroundColor Yellow
Write-Host "Runtime identifier: $RuntimeIdentifier" -ForegroundColor Yellow
Write-Host "Mode: $Mode" -ForegroundColor Yellow
Write-Host "Work directory: $workRoot" -ForegroundColor Yellow

$packArgs = @(
    "pack"
    $projectPath
    "--configuration"
    $Configuration
    "--output"
    $packPath
)

Write-Host "Packing the library..." -ForegroundColor Cyan
& dotnet @packArgs
if ($LASTEXITCODE -ne 0) {
    throw "dotnet pack failed with exit code $LASTEXITCODE."
}

$packageFile = Get-ChildItem -Path $packPath -Filter *.nupkg -File |
    Where-Object { -not $_.Name.EndsWith(".symbols.nupkg", [System.StringComparison]::OrdinalIgnoreCase) } |
    Sort-Object Name |
    Select-Object -First 1

if ($null -eq $packageFile) {
    throw "No .nupkg package was produced in '$packPath'."
}

$packageIdentity = Get-NupkgIdentity -PackagePath $packageFile.FullName
Write-Host "Packed package: $($packageIdentity.Id) $($packageIdentity.Version)" -ForegroundColor Yellow

$consumerFiles = New-AotConsumerProject -ConsumerPath $consumerPath -TargetFramework $TargetFramework -PackageId $packageIdentity.Id -PackageVersion $packageIdentity.Version -PackageSourcePath $packPath

$visualStudioInstallPath = Get-VisualStudioInstallPath
$fallbackEnvironment = $null
if ($Mode -eq "Fallback") {
    if ([string]::IsNullOrWhiteSpace($visualStudioInstallPath)) {
        throw "Fallback NativeAOT mode requires a Visual Studio installation with VC tooling."
    }

    $fallbackEnvironment = Get-FallbackNativeAotEnvironment -VisualStudioInstallPath $visualStudioInstallPath
    Write-Host "Fallback environment will use:" -ForegroundColor Cyan
    Write-Host "  Visual Studio: $($fallbackEnvironment.VisualStudioInstallPath)" -ForegroundColor Gray
    if ($null -ne $fallbackEnvironment.MsvcRoot) {
        Write-Host "  MSVC root:     $($fallbackEnvironment.MsvcRoot)" -ForegroundColor Gray
    }
    if ($null -ne $fallbackEnvironment.ScopeCppSdkRoot) {
        Write-Host "  ScopeCppSDK:   $($fallbackEnvironment.ScopeCppSdkRoot)" -ForegroundColor Gray
    }
    if ($null -ne $fallbackEnvironment.WindowsSdkRoot) {
        Write-Host "  Windows SDK:   $($fallbackEnvironment.WindowsSdkRoot)" -ForegroundColor Gray
    }
}

$didRunFallback = $false
switch ($Mode) {
    "Regular" {
        Invoke-AotPublish -ConsumerProjectPath $consumerFiles.ProjectPath -ConsumerPath $consumerPath -PublishPath $regularPublishPath -Configuration $Configuration -RuntimeIdentifier $RuntimeIdentifier
    }
    "Fallback" {
        Invoke-AotPublish -ConsumerProjectPath $consumerFiles.ProjectPath -ConsumerPath $consumerPath -PublishPath $fallbackPublishPath -Configuration $Configuration -RuntimeIdentifier $RuntimeIdentifier -UseFallbackEnvironment -FallbackEnvironment $fallbackEnvironment
        $didRunFallback = $true
    }
    "Auto" {
        try {
            Invoke-AotPublish -ConsumerProjectPath $consumerFiles.ProjectPath -ConsumerPath $consumerPath -PublishPath $regularPublishPath -Configuration $Configuration -RuntimeIdentifier $RuntimeIdentifier
        } catch {
            Write-Warning "Regular AOT publish failed: $($_.Exception.Message)"
            Write-Warning "Retrying in fallback mode with explicit toolchain paths."
            if ([string]::IsNullOrWhiteSpace($visualStudioInstallPath)) {
                throw "Regular NativeAOT publish failed and no Visual Studio installation was found for fallback mode."
            }

            if ($null -eq $fallbackEnvironment) {
                $fallbackEnvironment = Get-FallbackNativeAotEnvironment -VisualStudioInstallPath $visualStudioInstallPath
                Write-Host "Fallback environment will use:" -ForegroundColor Cyan
                Write-Host "  Visual Studio: $($fallbackEnvironment.VisualStudioInstallPath)" -ForegroundColor Gray
                if ($null -ne $fallbackEnvironment.MsvcRoot) {
                    Write-Host "  MSVC root:     $($fallbackEnvironment.MsvcRoot)" -ForegroundColor Gray
                }
                if ($null -ne $fallbackEnvironment.ScopeCppSdkRoot) {
                    Write-Host "  ScopeCppSDK:   $($fallbackEnvironment.ScopeCppSdkRoot)" -ForegroundColor Gray
                }
                if ($null -ne $fallbackEnvironment.WindowsSdkRoot) {
                    Write-Host "  Windows SDK:   $($fallbackEnvironment.WindowsSdkRoot)" -ForegroundColor Gray
                }
            }

            Invoke-AotPublish -ConsumerProjectPath $consumerFiles.ProjectPath -ConsumerPath $consumerPath -PublishPath $fallbackPublishPath -Configuration $Configuration -RuntimeIdentifier $RuntimeIdentifier -UseFallbackEnvironment -FallbackEnvironment $fallbackEnvironment
            $didRunFallback = $true
        }
    }
}

if ($didRunFallback) {
    Write-Host "Fallback NativeAOT publish completed successfully." -ForegroundColor Green
} else {
    Write-Host "Regular NativeAOT publish completed successfully." -ForegroundColor Green
}
