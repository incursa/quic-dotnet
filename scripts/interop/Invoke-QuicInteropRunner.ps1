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
    [string]$ArtifactsRoot
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
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Values
    )

    return @(
        foreach ($value in $Values) {
            if ($null -eq $value) {
                continue
            }

            foreach ($item in ($value -split ',')) {
                $trimmed = $item.Trim()
                if (-not [string]::IsNullOrWhiteSpace($trimmed)) {
                    $trimmed
                }
            }
        }
    )
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

$runnerSupportedTestCases = @(
    'handshake',
    'retry',
    'transfer'
)

Assert-CommandAvailable -Name 'docker'

$pythonCommand = @('python', 'python3', 'py') |
    ForEach-Object { Get-Command $_ -ErrorAction SilentlyContinue } |
    Select-Object -First 1

if ($null -eq $pythonCommand) {
    throw 'python is required but was not found on PATH.'
}

if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
}

if ([string]::IsNullOrWhiteSpace($RunnerRoot)) {
    $RunnerRoot = Join-Path (Split-Path (Split-Path $RepoRoot -Parent) -Parent) 'quic-interop\quic-interop-runner'
}

if ([string]::IsNullOrWhiteSpace($ArtifactsRoot)) {
    $ArtifactsRoot = Join-Path $RepoRoot 'artifacts\interop-runner'
}

if (-not (Test-Path -LiteralPath $RepoRoot)) {
    throw "Repository root was not found at '$RepoRoot'."
}

if (-not (Test-Path -LiteralPath $RunnerRoot)) {
    throw "Interop runner checkout was not found at '$RunnerRoot'."
}

$repoRootResolved = (Resolve-Path -LiteralPath $RepoRoot).Path
$runnerRootResolved = (Resolve-Path -LiteralPath $RunnerRoot).Path
$artifactRootResolved = [System.IO.Path]::GetFullPath($ArtifactsRoot)
$dockerBuildContextRoot = Split-Path $repoRootResolved -Parent

$registry = Get-RunnerImplementationRegistry -RunnerRootPath $runnerRootResolved
$TestCases = Normalize-StringList -Values $TestCases
if ($TestCases.Count -eq 0) {
    throw 'At least one testcase must be requested.'
}

$PeerImplementationSlots = Normalize-StringList -Values $PeerImplementationSlots
if ($PeerImplementationSlots.Count -eq 0 -and $LocalRole -ne 'both') {
    throw 'PeerImplementationSlots must include at least one implementation when LocalRole is client or server.'
}

if ([string]::IsNullOrWhiteSpace($ImplementationSlot)) {
    $ImplementationSlot = switch ($LocalRole) {
        'both' { 'quic-go' }
        'client' { 'chrome' }
        'server' { 'nginx' }
    }
}

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

$unsupportedRequestedTestCases = @(
    $TestCases |
        Where-Object { $_ -notin $runnerSupportedTestCases }
)

if ($unsupportedRequestedTestCases.Count -gt 0) {
    throw "Requested testcase(s) $($unsupportedRequestedTestCases -join ', ') are not part of the runner-recognized local subset for this helper. Supported testcase subset: $($runnerSupportedTestCases -join ', ')."
}

$dockerfilePath = Join-Path $repoRootResolved 'src\Incursa.Quic.InteropHarness\Dockerfile'
if (-not (Test-Path -LiteralPath $dockerfilePath)) {
    throw "Harness Dockerfile was not found at '$dockerfilePath'."
}

$runnerScriptPath = Join-Path $runnerRootResolved 'run.py'
if (-not (Test-Path -LiteralPath $runnerScriptPath)) {
    throw "Interop runner entry point was not found at '$runnerScriptPath'."
}

$null = New-Item -Path $artifactRootResolved -ItemType Directory -Force
$runStamp = Get-Date -Format 'yyyyMMdd-HHmmssfff'
$safeSlotName = "$LocalRole-$ImplementationSlot" -replace '[^A-Za-z0-9_.-]', '-'
$runRoot = Join-Path $artifactRootResolved "$runStamp-$safeSlotName"
New-Item -Path $runRoot -ItemType Directory -Force | Out-Null

$runnerLogDir = Join-Path $runRoot 'runner-logs'

$dockerBuildLog = Join-Path $runRoot 'docker-build.log'
$runnerMarkdown = Join-Path $runRoot 'runner-report.md'
$runnerStdErr = Join-Path $runRoot 'runner.stderr.log'
$runnerJson = Join-Path $runRoot 'runner-report.json'
$invocationLog = Join-Path $runRoot 'invocation.txt'
$artifactTreeLog = Join-Path $runRoot 'artifact-tree.txt'
$runnerShimPath = Join-Path $runRoot 'runner-shim.py'

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

@"
RepoRoot: $repoRootResolved
RunnerRoot: $runnerRootResolved
LocalRole: $LocalRole
LocalImplementationSlot: $ImplementationSlot
PeerImplementationSlots: $($PeerImplementationSlots -join ',')
ImageTag: $ImageTag
TestCases: $($TestCases -join ',')
ArtifactsRoot: $artifactRootResolved
RunRoot: $runRoot
RunnerShim: $runnerShimPath
"@ | Set-Content -LiteralPath $invocationLog

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
    $runnerExitCode = 1
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

    $runnerArgs = @(
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

    & $pythonCommand -X utf8 $runnerShimPath @runnerArgs 1> $runnerMarkdown 2> $runnerStdErr
    $runnerExitCode = $LASTEXITCODE
}
finally {
    Pop-Location
    if (Test-Path -LiteralPath $runnerShimPath) {
        Remove-Item -LiteralPath $runnerShimPath -Force -ErrorAction SilentlyContinue
    }
}

Write-ArtifactTree -RootPath $runRoot -OutputPath $artifactTreeLog

if (-not (Test-Path -LiteralPath $runnerJson)) {
    throw "quic-interop-runner did not produce '$runnerJson'. Check '$runnerMarkdown' and '$runnerStdErr' for details."
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

exit $runnerExitCode
