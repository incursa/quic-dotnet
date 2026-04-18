[CmdletBinding()]
param(
    [string]$RepoRoot,
    [string]$RunnerRoot,
    [string]$ImplementationSlot = '',
    [ValidateSet('both', 'client', 'server')]
    [string]$LocalRole = 'both',
    [string[]]$PeerImplementationSlots = @(
        'quic-go',
        'msquic'
    ),
    [string]$ImageTag = 'incursa-quic-interop-harness:local',
    [string[]]$TestCases = @(
        'handshake',
        'retry',
        'transfer'
    ),
    [string]$ArtifactsRoot,
    [Alias('PlanOnly')]
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-CommandAvailable {
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "$Name is required but was not found on PATH."
    }
}

function Get-RepoRelativePath {
    param(
        [Parameter(Mandatory)]
        [string]$Root,

        [Parameter(Mandatory)]
        [string]$Path
    )

    if ($Path.StartsWith($Root, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $Path.Substring($Root.Length).TrimStart('\', '/')
    }

    return $Path
}

function Get-RunnerImplementationRegistry {
    param(
        [Parameter(Mandatory)]
        [string]$RunnerRootPath
    )

    $registryPath = Join-Path $RunnerRootPath 'implementations_quic.json'
    if (-not (Test-Path -LiteralPath $registryPath)) {
        throw "Runner implementation registry was not found at '$registryPath'."
    }

    return @{
        Path = $registryPath
        Data = (Get-Content -LiteralPath $registryPath -Raw | ConvertFrom-Json)
    }
}

function Normalize-StringList {
    param(
        [AllowNull()]
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Values
    )

    if ($null -eq $Values) {
        return @()
    }

    $normalizedValues = [System.Collections.Generic.List[string]]::new()

    foreach ($value in $Values) {
        if ($null -eq $value) {
            continue
        }

        foreach ($item in ($value -split ',')) {
            $trimmed = $item.Trim()
            if (-not [string]::IsNullOrWhiteSpace($trimmed)) {
                $normalizedValues.Add($trimmed)
            }
        }
    }

    return $normalizedValues.ToArray()
}

function Get-RunnerImplementationRole {
    param(
        [Parameter(Mandatory)]
        [object]$RegistryData,

        [Parameter(Mandatory)]
        [string]$SlotName
    )

    $slot = $RegistryData.PSObject.Properties[$SlotName]
    if ($null -eq $slot) {
        return $null
    }

    return [string]$slot.Value.role
}

function Get-EffectivePath {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    try {
        return (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    }
    catch {
        return $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    }
}

function Get-InteropRunnerExecutionPlan {
    param(
        [Parameter(Mandatory)]
        [string]$RepoRootResolved,

        [Parameter(Mandatory)]
        [string]$RunnerRootResolved,

        [Parameter(Mandatory)]
        [string]$ArtifactRootResolved,

        [Parameter(Mandatory)]
        [string]$LocalRole,

        [Parameter(Mandatory)]
        [string]$ImplementationSlot,

        [Parameter(Mandatory)]
        [string[]]$PeerImplementationSlots,

        [Parameter(Mandatory)]
        [string[]]$TestCases,

        [Parameter(Mandatory)]
        [string]$ImageTag,

        [Parameter(Mandatory)]
        [string]$RunStamp
    )

    $runnerClientImplementations = @()
    $runnerServerImplementations = @()

    if ($LocalRole -eq 'both') {
        $runnerClientImplementations = @($ImplementationSlot)
        $runnerServerImplementations = @($ImplementationSlot)
    }
    elseif ($LocalRole -eq 'client') {
        $runnerClientImplementations = @($ImplementationSlot)
        $runnerServerImplementations = @($PeerImplementationSlots)
    }
    else {
        $runnerClientImplementations = @($PeerImplementationSlots)
        $runnerServerImplementations = @($ImplementationSlot)
    }

    $safeSlotName = "$LocalRole-$ImplementationSlot" -replace '[^A-Za-z0-9_.-]', '-'
    $runRoot = Join-Path $ArtifactRootResolved "$RunStamp-$safeSlotName"
    $runnerLogDir = Join-Path $runRoot 'runner-logs'
    $dockerBuildLog = Join-Path $runRoot 'docker-build.log'
    $runnerMarkdown = Join-Path $runRoot 'runner-report.md'
    $runnerStdErr = Join-Path $runRoot 'runner.stderr.log'
    $runnerJson = Join-Path $runRoot 'runner-report.json'
    $invocationLog = Join-Path $runRoot 'invocation.txt'
    $artifactTreeLog = Join-Path $runRoot 'artifact-tree.txt'
    $runnerShimPath = Join-Path $runRoot 'runner-shim.py'
    $dockerBuildStageRoot = Join-Path ([System.IO.Path]::GetTempPath()) "interop-runner-build-$RunStamp"

    return [pscustomobject]@{
        RepoRoot = $RepoRootResolved
        RunnerRoot = $RunnerRootResolved
        LocalRole = $LocalRole
        LocalImplementationSlot = $ImplementationSlot
        PeerImplementationSlots = $PeerImplementationSlots
        RunnerClientImplementations = $runnerClientImplementations
        RunnerServerImplementations = $runnerServerImplementations
        ImageTag = $ImageTag
        TestCases = $TestCases
        ArtifactRoot = $ArtifactRootResolved
        RunRoot = $runRoot
        RunnerLogDir = $runnerLogDir
        DockerBuildLog = $dockerBuildLog
        RunnerMarkdown = $runnerMarkdown
        RunnerStdErr = $runnerStdErr
        RunnerJson = $runnerJson
        InvocationLog = $invocationLog
        ArtifactTreeLog = $artifactTreeLog
        RunnerShimPath = $runnerShimPath
        DockerfilePath = Join-Path $RepoRootResolved 'src\Incursa.Quic.InteropHarness\Dockerfile'
        RunnerScriptPath = Join-Path $RunnerRootResolved 'run.py'
        DockerBuildStageRoot = $dockerBuildStageRoot
        RunnerArgs = @(
            '-p'
            'quic'
            '-s'
            ($runnerServerImplementations -join ',')
            '-c'
            ($runnerClientImplementations -join ',')
            '-t'
            ($TestCases -join ',')
            '-r'
            "$ImplementationSlot=$ImageTag"
            '-l'
            $runnerLogDir
            '-j'
            $runnerJson
            '-m'
        )
    }
}

function Write-InteropRunnerPlan {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Plan
    )

    Write-Host ''
    Write-Host 'Interop runner plan-only.' -ForegroundColor Green
    Write-Host "  Repo root:                    $($Plan.RepoRoot)"
    Write-Host "  Runner root:                  $($Plan.RunnerRoot)"
    Write-Host "  Local role:                   $($Plan.LocalRole)"
    Write-Host "  Local implementation slot:     $($Plan.LocalImplementationSlot)"
    Write-Host "  Peer implementation slots:     $($Plan.PeerImplementationSlots -join ',')"
    Write-Host "  Runner client implementations: $($Plan.RunnerClientImplementations -join ',')"
    Write-Host "  Runner server implementations: $($Plan.RunnerServerImplementations -join ',')"
    Write-Host "  Test cases:                   $($Plan.TestCases -join ',')"
    Write-Host "  Artifact root:                $($Plan.ArtifactRoot)"
    Write-Host "  Run root:                     $($Plan.RunRoot)"
    Write-Host "  Dockerfile:                   $($Plan.DockerfilePath)"
    Write-Host "  Runner script:                $($Plan.RunnerScriptPath)"
    Write-Host "  Image tag:                    $($Plan.ImageTag)"
    Write-Host '  Artifact files:'
    Write-Host "    Docker build log:           $($Plan.DockerBuildLog)"
    Write-Host "    Invocation log:             $($Plan.InvocationLog)"
    Write-Host "    Runner JSON:                $($Plan.RunnerJson)"
    Write-Host "    Runner Markdown:            $($Plan.RunnerMarkdown)"
    Write-Host "    Runner stderr:              $($Plan.RunnerStdErr)"
    Write-Host "    Runner logs:                $($Plan.RunnerLogDir)"
    Write-Host "    Artifact tree:              $($Plan.ArtifactTreeLog)"
    Write-Host "    Runner shim:                $($Plan.RunnerShimPath)"
    Write-Host '  Runner args:'
    foreach ($arg in $Plan.RunnerArgs) {
        Write-Host "    $arg"
    }
    Write-Host ''
    Write-Host 'Plan-only mode completed without Docker build, runner checkout validation, or runner launch.' -ForegroundColor Yellow
}

function Write-ArtifactTree {
    param(
        [Parameter(Mandatory)]
        [string]$RootPath,

        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    $lines = @(
        Get-ChildItem -LiteralPath $RootPath -File -Recurse -ErrorAction SilentlyContinue |
            Sort-Object FullName |
            ForEach-Object {
                $relativePath = Get-RepoRelativePath -Root $RootPath -Path $_.FullName
                '{0} ({1} bytes)' -f $relativePath, $_.Length
            }
    )

    if ($lines.Count -eq 0) {
        $lines = @('(no files)')
    }

    $lines | Set-Content -LiteralPath $OutputPath
}

function Write-InteropRunnerInvocation {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Plan,

        [Parameter(Mandatory)]
        [string]$Path
    )

    $runnerArgsLines = $Plan.RunnerArgs | ForEach-Object { "  $_" }

    @"
RepoRoot: $($Plan.RepoRoot)
RunnerRoot: $($Plan.RunnerRoot)
LocalRole: $($Plan.LocalRole)
LocalImplementationSlot: $($Plan.LocalImplementationSlot)
PeerImplementationSlots: $($Plan.PeerImplementationSlots -join ',')
ImageTag: $($Plan.ImageTag)
TestCases: $($Plan.TestCases -join ',')
ArtifactsRoot: $($Plan.ArtifactRoot)
RunRoot: $($Plan.RunRoot)
RunnerJson: $($Plan.RunnerJson)
RunnerMarkdown: $($Plan.RunnerMarkdown)
RunnerStdErr: $($Plan.RunnerStdErr)
RunnerLogDir: $($Plan.RunnerLogDir)
ArtifactTreeLog: $($Plan.ArtifactTreeLog)
RunnerShim: $($Plan.RunnerShimPath)
RunnerArgs:
$($runnerArgsLines -join [Environment]::NewLine)
"@ | Set-Content -LiteralPath $Path -Encoding utf8
}

function Get-InteropRunnerOutputValidation {
    param(
        [Parameter(Mandatory)]
        [string]$RunnerJson,

        [Parameter(Mandatory)]
        [string]$RunnerMarkdown,

        [Parameter(Mandatory)]
        [string]$RunnerStdErr,

        [Parameter(Mandatory)]
        [string]$RunnerLogDir
    )

    $missing = [System.Collections.Generic.List[string]]::new()
    $problems = [System.Collections.Generic.List[string]]::new()

    if (-not (Test-Path -LiteralPath $RunnerJson)) {
        $missing.Add("runner JSON at '$RunnerJson'")
    }
    else {
        $jsonItem = Get-Item -LiteralPath $RunnerJson
        if ($jsonItem.Length -le 0) {
            $problems.Add("runner JSON at '$RunnerJson' was empty")
        }
        else {
            try {
                $null = Get-Content -LiteralPath $RunnerJson -Raw | ConvertFrom-Json -ErrorAction Stop
            }
            catch {
                $problems.Add("runner JSON at '$RunnerJson' was not valid JSON: $($_.Exception.Message)")
            }
        }
    }

    if (-not (Test-Path -LiteralPath $RunnerMarkdown)) {
        $missing.Add("runner Markdown at '$RunnerMarkdown'")
    }
    else {
        $markdownItem = Get-Item -LiteralPath $RunnerMarkdown
        if ($markdownItem.Length -le 0) {
            $problems.Add("runner Markdown at '$RunnerMarkdown' was empty")
        }
    }

    if (-not (Test-Path -LiteralPath $RunnerStdErr)) {
        $missing.Add("runner stderr log at '$RunnerStdErr'")
    }

    if (-not (Test-Path -LiteralPath $RunnerLogDir)) {
        $missing.Add("runner log directory at '$RunnerLogDir'")
    }
    else {
        $runnerLogFiles = Get-ChildItem -LiteralPath $RunnerLogDir -File -Recurse -ErrorAction SilentlyContinue
        if (@($runnerLogFiles).Count -eq 0) {
            $problems.Add("runner log directory at '$RunnerLogDir' did not contain any files")
        }
    }

    return [pscustomobject]@{
        Success = ($missing.Count -eq 0 -and $problems.Count -eq 0)
        Missing = $missing.ToArray()
        Problems = $problems.ToArray()
    }
}

function Write-InteropRunnerFailureSummary {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Plan,

        [Parameter()]
        [pscustomobject]$OutputValidation,

        [Parameter()]
        [Nullable[int]]$RunnerExitCode,

        [Parameter()]
        [string]$Reason
    )

    Write-Host ''
    Write-Host 'Interop runner helper failed.' -ForegroundColor Red

    if (-not [string]::IsNullOrWhiteSpace($Reason)) {
        Write-Host "  Reason: $Reason"
    }

    if ($null -ne $RunnerExitCode) {
        Write-Host "  Runner exit code: $RunnerExitCode"
    }

    Write-Host "  Run root:        $($Plan.RunRoot)"
    Write-Host "  Invocation log:  $($Plan.InvocationLog)"
    Write-Host "  Artifact tree:   $($Plan.ArtifactTreeLog)"

    if ($null -ne $OutputValidation) {
        if (@($OutputValidation.Missing).Count -gt 0) {
            Write-Host "  Missing outputs: $($OutputValidation.Missing -join ', ')"
        }

        if (@($OutputValidation.Problems).Count -gt 0) {
            Write-Host "  Output issues:   $($OutputValidation.Problems -join ' | ')"
        }
    }

    Write-Host "  Runner stderr:   $($Plan.RunnerStdErr)"
    Write-Host '  Evidence was preserved in the run root for post-failure inspection.'
}

$runnerSupportedTestCases = @(
    'handshake',
    'retry',
    'transfer'
)

if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
}

if (-not (Test-Path -LiteralPath $RepoRoot)) {
    throw "Repository root was not found at '$RepoRoot'."
}

$repoRootResolved = (Resolve-Path -LiteralPath $RepoRoot).Path

if ([string]::IsNullOrWhiteSpace($RunnerRoot)) {
    $RunnerRoot = Join-Path (Split-Path (Split-Path $repoRootResolved -Parent) -Parent) 'quic-interop\quic-interop-runner'
}

if ([string]::IsNullOrWhiteSpace($ArtifactsRoot)) {
    $ArtifactsRoot = Join-Path $repoRootResolved 'artifacts\interop-runner'
}

$TestCases = Normalize-StringList -Values $TestCases
if ($null -eq $TestCases -or @($TestCases).Count -eq 0) {
    throw 'At least one testcase must be requested.'
}

$PeerImplementationSlots = Normalize-StringList -Values $PeerImplementationSlots
if (($null -eq $PeerImplementationSlots -or @($PeerImplementationSlots).Count -eq 0) -and $LocalRole -ne 'both') {
    throw 'PeerImplementationSlots must include at least one implementation when LocalRole is client or server.'
}

if ([string]::IsNullOrWhiteSpace($ImplementationSlot)) {
    $ImplementationSlot = switch ($LocalRole) {
        'both' { 'quic-go' }
        'client' { 'chrome' }
        'server' { 'nginx' }
    }
}

$unsupportedRequestedTestCases = @(
    $TestCases |
        Where-Object { $_ -notin $runnerSupportedTestCases }
)

if (@($unsupportedRequestedTestCases).Count -gt 0) {
    throw "Requested testcase(s) $($unsupportedRequestedTestCases -join ', ') are not part of the runner-recognized local subset for this helper. Supported testcase subset: $($runnerSupportedTestCases -join ', ')."
}

$runnerRootResolved = Get-EffectivePath -Path $RunnerRoot
$artifactRootResolved = Get-EffectivePath -Path $ArtifactsRoot
$runStamp = Get-Date -Format 'yyyyMMdd-HHmmssfff'
$executionPlan = Get-InteropRunnerExecutionPlan `
    -RepoRootResolved $repoRootResolved `
    -RunnerRootResolved $runnerRootResolved `
    -ArtifactRootResolved $artifactRootResolved `
    -LocalRole $LocalRole `
    -ImplementationSlot $ImplementationSlot `
    -PeerImplementationSlots $PeerImplementationSlots `
    -TestCases $TestCases `
    -ImageTag $ImageTag `
    -RunStamp $runStamp

if ($DryRun) {
    Write-InteropRunnerPlan -Plan $executionPlan
    exit 0
}

$null = New-Item -Path $artifactRootResolved -ItemType Directory -Force
New-Item -Path $executionPlan.RunRoot -ItemType Directory -Force | Out-Null

$runRoot = $executionPlan.RunRoot
$runnerLogDir = $executionPlan.RunnerLogDir
$dockerBuildLog = $executionPlan.DockerBuildLog
$runnerMarkdown = $executionPlan.RunnerMarkdown
$runnerStdErr = $executionPlan.RunnerStdErr
$runnerJson = $executionPlan.RunnerJson
$artifactTreeLog = $executionPlan.ArtifactTreeLog
$runnerShimPath = $executionPlan.RunnerShimPath
$dockerBuildStageRoot = $executionPlan.DockerBuildStageRoot
$runnerArgs = $executionPlan.RunnerArgs

$runnerExitCode = $null
$runnerOutputValidation = $null
$runnerFailureReason = $null
$runnerFailureExitCode = 0

try {
    Write-InteropRunnerInvocation -Plan $executionPlan -Path $executionPlan.InvocationLog

    $dockerfilePath = $executionPlan.DockerfilePath
    if (-not (Test-Path -LiteralPath $dockerfilePath)) {
        throw "Harness Dockerfile was not found at '$dockerfilePath'."
    }

    Assert-CommandAvailable -Name 'docker'

    $pythonCommand = @('python', 'python3', 'py') |
        ForEach-Object { Get-Command $_ -ErrorAction SilentlyContinue } |
        Select-Object -First 1

    if ($null -eq $pythonCommand) {
        throw 'python is required but was not found on PATH.'
    }

    if (-not (Test-Path -LiteralPath $runnerRootResolved)) {
        throw "Interop runner checkout was not found at '$runnerRootResolved'."
    }

    $registry = Get-RunnerImplementationRegistry -RunnerRootPath $runnerRootResolved

    $localRoleCompatibleSlots = switch ($LocalRole) {
        'both' { @('both') }
        'client' { @('both', 'client') }
        'server' { @('both', 'server') }
    }

    $peerRoleCompatibleSlots = switch ($LocalRole) {
        'both' { @('both') }
        'client' { @('both', 'server') }
        'server' { @('both', 'client') }
    }

    $localImplementationRole = Get-RunnerImplementationRole -RegistryData $registry.Data -SlotName $ImplementationSlot
    if ($null -eq $localImplementationRole) {
        throw "Implementation slot '$ImplementationSlot' was not found in '$($registry.Path)'."
    }

    if ($localImplementationRole -notin $localRoleCompatibleSlots) {
        throw "Implementation slot '$ImplementationSlot' is role '$localImplementationRole' which is not compatible with LocalRole '$LocalRole'."
    }

    if ($LocalRole -ne 'both') {
        foreach ($peerImplementationSlot in $PeerImplementationSlots) {
            if ($peerImplementationSlot -eq $ImplementationSlot) {
                throw "LocalRole '$LocalRole' requires the local replacement slot '$ImplementationSlot' to differ from the peer implementation slot list."
            }

            $peerImplementationRole = Get-RunnerImplementationRole -RegistryData $registry.Data -SlotName $peerImplementationSlot
            if ($null -eq $peerImplementationRole) {
                throw "Peer implementation slot '$peerImplementationSlot' was not found in '$($registry.Path)'."
            }

            if ($peerImplementationRole -notin $peerRoleCompatibleSlots) {
                throw "Peer implementation slot '$peerImplementationSlot' is role '$peerImplementationRole' which is not compatible with LocalRole '$LocalRole'."
            }
        }
    }

    $runnerScriptPath = $executionPlan.RunnerScriptPath
    if (-not (Test-Path -LiteralPath $runnerScriptPath)) {
        throw "Interop runner entry point was not found at '$runnerScriptPath'."
    }

    $runnerShimContent = @'
import os
import random
import shutil
import string
import subprocess
import sys
import tempfile

sys.path.insert(0, os.getcwd())

import testcase
import testcases_quic

_real_subprocess_run = subprocess.run


def _split_shell_words(command):
    words = []
    current = []
    in_quotes = False

    for char in command:
        if char == '"':
            in_quotes = not in_quotes
        elif char.isspace() and not in_quotes:
            if current:
                words.append("".join(current))
                current = []
        else:
            current.append(char)

    if current:
        words.append("".join(current))

    return words


def _parse_env_prefix_command(command):
    tokens = _split_shell_words(command)
    env_overrides = {}
    command_tokens = []

    for index, token in enumerate(tokens):
        if command_tokens:
            command_tokens.append(token)
            continue

        if "=" in token and not token.startswith("-"):
            name, value = token.split("=", 1)
            if name and (name[0].isalpha() or name[0] == "_") and all(
                ch.isalnum() or ch == "_" for ch in name[1:]
            ):
                env_overrides[name] = value
                continue

        command_tokens = tokens[index:]
        break

    if not command_tokens:
        return None

    return env_overrides, command_tokens


def _patched_run(*popenargs, **kwargs):
    if os.name == "nt" and kwargs.get("shell") and popenargs and isinstance(popenargs[0], str):
        parsed = _parse_env_prefix_command(popenargs[0])
        if parsed is not None:
            env_overrides, command_tokens = parsed
            new_kwargs = dict(kwargs)
            new_kwargs.pop("shell", None)

            env = os.environ.copy()
            env.update(env_overrides)
            if new_kwargs.get("env") is not None:
                env.update(new_kwargs["env"])
            new_kwargs["env"] = env

            return _real_subprocess_run(command_tokens, **new_kwargs)

    return _real_subprocess_run(*popenargs, **kwargs)


_runner_tmp_root = os.path.join(os.environ.get("TEMP", tempfile.gettempdir()), "quic-interop-runner")
os.makedirs(_runner_tmp_root, exist_ok=True)
_real_temporary_directory = tempfile.TemporaryDirectory
_real_named_temporary_file = tempfile.NamedTemporaryFile


def _normalize_temp_kwargs(kwargs):
    if kwargs.get("dir") == "/tmp":
        normalized = dict(kwargs)
        normalized["dir"] = _runner_tmp_root
        return normalized

    return kwargs


def _patched_temporary_directory(*args, **kwargs):
    return _real_temporary_directory(*args, **_normalize_temp_kwargs(kwargs))


def _patched_named_temporary_file(*args, **kwargs):
    normalized = _normalize_temp_kwargs(kwargs)
    if normalized is kwargs:
        return _real_named_temporary_file(*args, **kwargs)

    prefix = normalized.get("prefix", "tmp")
    suffix = normalized.get("suffix", "")
    dir_path = normalized["dir"]
    os.makedirs(dir_path, exist_ok=True)
    fd, path = tempfile.mkstemp(prefix=prefix, suffix=suffix, dir=dir_path)
    os.close(fd)

    class _TempPathProxy:
        def __init__(self, name):
            self.name = name

        def close(self):
            return None

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

    return _TempPathProxy(path)


tempfile.TemporaryDirectory = _patched_temporary_directory
tempfile.NamedTemporaryFile = _patched_named_temporary_file


def _run_openssl(args):
    completed = _real_subprocess_run(
        ["openssl", *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if completed.returncode != 0:
        message = completed.stdout.strip()
        if not message:
            message = "openssl " + " ".join(args) + f" failed with exit code {completed.returncode}."
        raise RuntimeError(message)


def generate_cert_chain(directory, length=1):
    directory = os.path.abspath(directory)
    os.makedirs(directory, exist_ok=True)
    cert_config = os.path.join(os.getcwd(), "cert_config.txt")
    os.environ["OPENSSL_CONF"] = cert_config

    root_ca_key = os.path.join(directory, "ca_0.key")
    root_ca_cert = os.path.join(directory, "cert_0.pem")
    _run_openssl(["ecparam", "-name", "prime256v1", "-genkey", "-out", root_ca_key])
    _run_openssl([
        "req",
        "-x509",
        "-sha256",
        "-nodes",
        "-days",
        "10",
        "-key",
        root_ca_key,
        "-out",
        root_ca_cert,
        "-subj",
        "/O=interop runner Root Certificate Authority/",
        "-config",
        cert_config,
        "-extensions",
        "v3_ca",
    ])

    fakedns = ""
    if length != 1:
        alphabet = string.ascii_letters + string.digits
        fakedns = "," + ",".join(
            "DNS:" + "".join(random.choice(alphabet) for _ in range(250))
            for _ in range(20)
        )

    for i in range(1, length + 1):
        subject = f"interop runner intermediate {i}" if i < length else "interop runner leaf"
        ca_key = os.path.join(directory, f"ca_{i}.key")
        csr = os.path.join(directory, "cert.csr")
        cert_out = os.path.join(directory, f"cert_{i}.pem")

        _run_openssl(["ecparam", "-name", "prime256v1", "-genkey", "-out", ca_key])
        _run_openssl([
            "req",
            "-out",
            csr,
            "-new",
            "-key",
            ca_key,
            "-nodes",
            "-subj",
            f"/O={subject}/",
        ])

        parent_index = i - 1
        parent_cert = os.path.join(directory, f"cert_{parent_index}.pem")
        parent_key = os.path.join(directory, f"ca_{parent_index}.key")

        if i < length:
            _run_openssl([
                "x509",
                "-req",
                "-sha256",
                "-days",
                "10",
                "-in",
                csr,
                "-out",
                cert_out,
                "-CA",
                parent_cert,
                "-CAkey",
                parent_key,
                "-CAcreateserial",
                "-extfile",
                cert_config,
                "-extensions",
                "v3_ca",
            ])
        else:
            with tempfile.NamedTemporaryFile("w", delete=False, suffix=".cnf", encoding="utf-8") as extfile:
                extfile.write("subjectAltName=DNS:server,DNS:server4,DNS:server6,DNS:server46" + fakedns + "\n")
                extfile_path = extfile.name
            try:
                _run_openssl([
                    "x509",
                    "-req",
                    "-sha256",
                    "-days",
                    "10",
                    "-in",
                    csr,
                    "-out",
                    cert_out,
                    "-CA",
                    parent_cert,
                    "-CAkey",
                    parent_key,
                    "-CAcreateserial",
                    "-extfile",
                    extfile_path,
                ])
            finally:
                try:
                    os.unlink(extfile_path)
                except FileNotFoundError:
                    pass

    shutil.move(root_ca_cert, os.path.join(directory, "ca.pem"))
    shutil.copyfile(os.path.join(directory, f"ca_{length}.key"), os.path.join(directory, "priv.key"))

    with open(os.path.join(directory, "cert.pem"), "wb") as combined:
        for i in range(length, 0, -1):
            cert_piece = os.path.join(directory, f"cert_{i}.pem")
            ca_piece = os.path.join(directory, f"ca_{i}.key")
            with open(cert_piece, "rb") as src:
                shutil.copyfileobj(src, combined)
            os.remove(cert_piece)
            os.remove(ca_piece)

    for stale in ("ca_0.key", "cert.csr"):
        try:
            os.remove(os.path.join(directory, stale))
        except FileNotFoundError:
            pass


testcase.generate_cert_chain = generate_cert_chain
testcases_quic.generate_cert_chain = generate_cert_chain
subprocess.run = _patched_run

import run

raise SystemExit(run.main())
'@

    Set-Content -LiteralPath $runnerShimPath -Value $runnerShimContent -Encoding utf8

    $dockerBuildStageRoot = Join-Path ([System.IO.Path]::GetTempPath()) "interop-runner-build-$runStamp"
    New-Item -Path $dockerBuildStageRoot -ItemType Directory -Force | Out-Null
    $stagingExcludes = @(
        '.git',
        'artifacts',
        'bin',
        'obj',
        '.vs',
        'TestResults',
        'node_modules'
    )

    & robocopy $repoRootResolved (Join-Path $dockerBuildStageRoot 'quic-dotnet') /MIR /NFL /NDL /NJH /NJS /NP /XD @stagingExcludes | Out-Null
    if ($LASTEXITCODE -ge 8) {
        throw "Failed to stage the quic-dotnet build context copy with robocopy exit code $LASTEXITCODE."
    }

    @"
**/.git
**/bin
**/obj
**/artifacts
**/TestResults
**/.vs
**/.idea
**/*.user
**/*.suo
"@ | Set-Content -LiteralPath (Join-Path $dockerBuildStageRoot '.dockerignore')

    $dockerBuildContextRoot = $dockerBuildStageRoot

    Write-Host "Building Incursa.Quic.InteropHarness image..." -ForegroundColor Cyan
    $dockerBuildArgs = @(
        'build'
        '--progress'
        'plain'
        '--file'
        $dockerfilePath
        '--tag'
        $ImageTag
        $dockerBuildContextRoot
    )

    & docker @dockerBuildArgs 2>&1 | Tee-Object -FilePath $dockerBuildLog
    if ($LASTEXITCODE -ne 0) {
        throw "docker build failed with exit code $LASTEXITCODE. See '$dockerBuildLog'."
    }

    Push-Location $runnerRootResolved
    try {
        Write-Host "Running quic-interop-runner locally..." -ForegroundColor Cyan
        & $pythonCommand -X utf8 $runnerShimPath @runnerArgs 1> $runnerMarkdown 2> $runnerStdErr
        $runnerExitCode = $LASTEXITCODE
    }
    finally {
        Pop-Location
        if (Test-Path -LiteralPath $runnerShimPath) {
            Remove-Item -LiteralPath $runnerShimPath -Force -ErrorAction SilentlyContinue
        }
    }

    $runnerOutputValidation = Get-InteropRunnerOutputValidation `
        -RunnerJson $runnerJson `
        -RunnerMarkdown $runnerMarkdown `
        -RunnerStdErr $runnerStdErr `
        -RunnerLogDir $runnerLogDir

    if (-not $runnerOutputValidation.Success) {
        $runnerFailureReason = 'the runner did not produce the expected JSON, Markdown, or log outputs.'
        $runnerFailureExitCode = 1
    }
    elseif ($runnerExitCode -ne 0) {
        $runnerFailureReason = 'the runner exited non-zero after producing the expected outputs.'
        $runnerFailureExitCode = $runnerExitCode
    }
}
catch {
    if ($null -eq $runnerFailureReason) {
        $runnerFailureReason = $_.Exception.Message
    }

    if ($runnerFailureExitCode -eq 0) {
        $runnerFailureExitCode = 1
    }
}
finally {
    if (Test-Path -LiteralPath $runRoot) {
        Write-ArtifactTree -RootPath $runRoot -OutputPath $artifactTreeLog
    }
}

if ($null -ne $runnerFailureReason) {
    Write-InteropRunnerFailureSummary `
        -Plan $executionPlan `
        -OutputValidation $runnerOutputValidation `
        -RunnerExitCode $runnerExitCode `
        -Reason $runnerFailureReason
    exit $runnerFailureExitCode
}

Write-Host ''
Write-Host 'Interop runner helper complete.' -ForegroundColor Green
Write-Host "  Exit code: $runnerExitCode"
Write-Host "  Artifact root: $runRoot"
Write-Host "  JSON report:   $runnerJson"
Write-Host "  Markdown:      $runnerMarkdown"
Write-Host "  Stderr log:    $runnerStdErr"
Write-Host "  Log directory:  $runnerLogDir"
Write-Host "  Build log:      $dockerBuildLog"
Write-Host "  Tree summary:   $artifactTreeLog"

exit 0
