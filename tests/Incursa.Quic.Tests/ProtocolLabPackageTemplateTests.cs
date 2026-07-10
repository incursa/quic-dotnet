// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Diagnostics;
using System.IO.Compression;
using System.Text.Json;
using System.Xml.Linq;

namespace Incursa.Quic.Tests;

public sealed class ProtocolLabPackageTemplateTests
{
    private static readonly string[] RawQuicScenarioIds =
    [
        "quic.transport.stream-throughput.1mb",
        "quic.transport.multiplex.100x64kb",
        "quic.transport.duplex-streams",
    ];

    private static readonly string[] Http3ScenarioIds =
    [
        "http3.payload.bytes.1kb",
        "http3.payload.bytes.64kb",
        "http3.payload.bytes.1mb",
    ];

    private static readonly string[] Http3LoadProfileIds =
    [
        "smoke",
        "local-regression",
        "local-comparison",
        "h3-small-payload-c32",
        "h3-small-payload-c128",
    ];

    [Fact]
    public void Raw_quic_package_template_advertises_transport_contract()
    {
        var repoRoot = FindRepoRoot();
        var packageTemplatePath = Path.Combine(repoRoot, "eng", "protocol-lab", "templates", "raw-quic", "protocol-lab-package.json");
        var internalTemplatePath = Path.Combine(repoRoot, "eng", "protocol-lab", "templates", "raw-quic", "protocol-lab.internal.json");
        var implementationTemplatePath = Path.Combine(repoRoot, "eng", "protocol-lab", "templates", "raw-quic", "implementations", "quic-dotnet-raw-dev.yaml");

        using var packageDocument = JsonDocument.Parse(File.ReadAllText(packageTemplatePath));
        var packageRoot = packageDocument.RootElement;
        Assert.Equal("protocol-lab-package-v2", packageRoot.GetProperty("schemaVersion").GetString());
        Assert.Equal("quic-dotnet-raw-dev", packageRoot.GetProperty("packageId").GetString());
        Assert.False(packageRoot.TryGetProperty("sourceRepository", out _));
        Assert.False(packageRoot.TryGetProperty("sourceCommit", out _));
        var providedImplementation = Assert.Single(packageRoot.GetProperty("providedImplementations").EnumerateArray());
        Assert.Equal("quic-dotnet-raw-dev", providedImplementation.GetProperty("implementationId").GetString());
        Assert.Equal(["quic"], ReadJsonStringArray(providedImplementation, "protocols"));
        Assert.Equal(RawQuicScenarioIds, ReadJsonStringArray(providedImplementation, "scenarios"));
        Assert.DoesNotContain("h3", ReadJsonStringArray(providedImplementation, "protocols"));
        Assert.DoesNotContain("http.core.plaintext", ReadJsonStringArray(providedImplementation, "scenarios"));
        Assert.DoesNotContain("http3.payload.bytes.64kb", ReadJsonStringArray(providedImplementation, "scenarios"));
        Assert.DoesNotContain("http3.payload.bytes.1mb", ReadJsonStringArray(providedImplementation, "scenarios"));
        Assert.False(packageRoot.TryGetProperty("supportedProtocols", out _));
        Assert.False(packageRoot.TryGetProperty("supportedWorkloadFamilies", out _));
        Assert.False(packageRoot.TryGetProperty("supportedScenarios", out _));
        Assert.False(packageRoot.TryGetProperty("capabilities", out _));
        var dependencies = packageRoot.GetProperty("dependencies");
        Assert.False(packageRoot.TryGetProperty("environments", out _));
        Assert.False(dependencies.TryGetProperty("requiresDotNet", out _));
        Assert.False(dependencies.TryGetProperty("requiresPwsh", out _));
        Assert.False(dependencies.TryGetProperty("requiresBash", out _));
        var runtimeRequirement = Assert.Single(dependencies.GetProperty("requiredCapabilities").EnumerateArray());
        Assert.Equal("libmsquic", runtimeRequirement.GetProperty("name").GetString());

        using var internalDocument = JsonDocument.Parse(File.ReadAllText(internalTemplatePath));
        var internalRoot = internalDocument.RootElement;
        Assert.Equal("protocol-lab-internal-execution-v1", internalRoot.GetProperty("schemaVersion").GetString());
        Assert.Equal("__SOURCE_REPOSITORY__", internalRoot.GetProperty("sourceRepository").GetString());
        Assert.Equal("__SOURCE_COMMIT__", internalRoot.GetProperty("sourceCommit").GetString());
        var environments = internalRoot.GetProperty("environments").EnumerateArray().ToArray();
        Assert.Equal(2, environments.Length);
        AssertPackageEnvironment(environments, "linux", "x64");
        AssertPackageEnvironment(environments, "windows", "x64");
        var executionDependencies = internalRoot.GetProperty("dependencies");
        Assert.True(executionDependencies.GetProperty("requiresDotNet").GetBoolean());
        Assert.True(executionDependencies.GetProperty("requiresPwsh").GetBoolean());
        Assert.False(executionDependencies.GetProperty("requiresBash").GetBoolean());
        var executionRuntimeRequirement = Assert.Single(executionDependencies.GetProperty("requiredCapabilities").EnumerateArray());
        Assert.Equal("libmsquic", executionRuntimeRequirement.GetProperty("name").GetString());

        var implementationYaml = File.ReadAllText(implementationTemplatePath);
        Assert.Contains("id: quic-dotnet-raw-dev", implementationYaml);
        Assert.Contains("targetContract: adapter-v1", implementationYaml);
        Assert.Contains("executable: pwsh", implementationYaml);
        Assert.Contains("scripts/run-current-platform.ps1", implementationYaml);
        Assert.DoesNotContain("executable: bin/linux-x64/Incursa.ProtocolLab.Adapters.IncursaRawQuic", implementationYaml);
        Assert.Contains("IncursaRawQuicServer", implementationYaml);
        Assert.Contains("quic", ReadYamlList(implementationYaml, "supportedProtocols"));
        Assert.Contains("quic.transport", ReadYamlList(implementationYaml, "supportedWorkloadFamilies"));
        Assert.Contains("quic.transport.stream-throughput.1mb", ReadYamlList(implementationYaml, "supportedScenarios"));
        Assert.Contains("quic.transport.multiplex.100x64kb", ReadYamlList(implementationYaml, "supportedScenarios"));
        Assert.Contains("quic.transport.duplex-streams", ReadYamlList(implementationYaml, "supportedScenarios"));
        Assert.Equal(RawQuicScenarioIds, ReadYamlList(implementationYaml, "supportedScenarios"));
        Assert.DoesNotContain("h3", ReadYamlList(implementationYaml, "supportedProtocols"));
        Assert.DoesNotContain("http.application", ReadYamlList(implementationYaml, "supportedWorkloadFamilies"));
        Assert.DoesNotContain("http.core.", implementationYaml);
        Assert.DoesNotContain("http3.", implementationYaml);
        Assert.DoesNotContain("managed-httpclient-h3-load", implementationYaml);
        Assert.Contains("quicTransport", ReadYamlList(implementationYaml, "capabilities"));
        Assert.Contains("quicStreams", ReadYamlList(implementationYaml, "capabilities"));
        Assert.Contains("quicMultiplexing", ReadYamlList(implementationYaml, "capabilities"));
        Assert.Contains("quicDuplex", ReadYamlList(implementationYaml, "capabilities"));
        Assert.Contains("server.stdout.txt", ReadYamlList(implementationYaml, "artifactExports"));
        Assert.Contains("server.stderr.txt", ReadYamlList(implementationYaml, "artifactExports"));
        Assert.Contains("server.command.txt", ReadYamlList(implementationYaml, "artifactExports"));
    }

    [Fact]
    public void Http3_package_template_stays_http3_only()
    {
        var repoRoot = FindRepoRoot();
        var packageTemplatePath = Path.Combine(repoRoot, "eng", "protocol-lab", "templates", "protocol-lab-package.json");
        var internalTemplatePath = Path.Combine(repoRoot, "eng", "protocol-lab", "templates", "protocol-lab.internal.json");
        var implementationTemplatePath = Path.Combine(repoRoot, "eng", "protocol-lab", "templates", "implementations", "quic-dotnet-dev.yaml");

        using var packageDocument = JsonDocument.Parse(File.ReadAllText(packageTemplatePath));
        Assert.Equal("protocol-lab-package-v2", packageDocument.RootElement.GetProperty("schemaVersion").GetString());
        Assert.Equal("quic-dotnet-dev", packageDocument.RootElement.GetProperty("packageId").GetString());
        Assert.False(packageDocument.RootElement.TryGetProperty("sourceRepository", out _));
        Assert.False(packageDocument.RootElement.TryGetProperty("sourceCommit", out _));
        var providedImplementation = Assert.Single(packageDocument.RootElement.GetProperty("providedImplementations").EnumerateArray());
        Assert.Equal("quic-dotnet-dev", providedImplementation.GetProperty("implementationId").GetString());
        Assert.Equal(["h3"], ReadJsonStringArray(providedImplementation, "protocols"));
        Assert.Equal(Http3ScenarioIds, ReadJsonStringArray(providedImplementation, "scenarios"));
        Assert.DoesNotContain("quic.transport.multiplex.100x64kb", ReadJsonStringArray(providedImplementation, "scenarios"));
        Assert.DoesNotContain("quic.transport.duplex-streams", ReadJsonStringArray(providedImplementation, "scenarios"));
        Assert.False(providedImplementation.TryGetProperty("loadProfileIds", out _));

        using var internalDocument = JsonDocument.Parse(File.ReadAllText(internalTemplatePath));
        Assert.Equal("__SOURCE_REPOSITORY__", internalDocument.RootElement.GetProperty("sourceRepository").GetString());
        Assert.Equal("__SOURCE_COMMIT__", internalDocument.RootElement.GetProperty("sourceCommit").GetString());
        var internalImplementation = Assert.Single(internalDocument.RootElement.GetProperty("providedImplementations").EnumerateArray());
        Assert.Equal("quic-dotnet-dev", internalImplementation.GetProperty("implementationId").GetString());
        Assert.Equal(["h3"], ReadJsonStringArray(internalImplementation, "protocols"));
        Assert.Equal(Http3ScenarioIds, ReadJsonStringArray(internalImplementation, "scenarios"));
        Assert.Equal(Http3LoadProfileIds, ReadJsonStringArray(internalImplementation, "loadProfileIds"));

        var implementationYaml = File.ReadAllText(implementationTemplatePath);
        Assert.Contains("id: quic-dotnet-dev", implementationYaml);
        Assert.Contains("h3", ReadYamlList(implementationYaml, "supportedProtocols"));
        Assert.Contains("http.application", ReadYamlList(implementationYaml, "supportedWorkloadFamilies"));
        Assert.Equal(Http3ScenarioIds, ReadYamlList(implementationYaml, "supportedScenarios"));
        Assert.Contains("httpPlaintext", ReadYamlList(implementationYaml, "capabilities"));
        Assert.Contains("httpJson", ReadYamlList(implementationYaml, "capabilities"));
        Assert.Contains("httpBytes", ReadYamlList(implementationYaml, "capabilities"));
        Assert.Contains("type: processStarted", implementationYaml);
        Assert.Contains("startupDelayMilliseconds: 2000", implementationYaml);
        Assert.DoesNotContain("quic", ReadYamlList(implementationYaml, "supportedProtocols"));
        Assert.DoesNotContain("quic.transport", ReadYamlList(implementationYaml, "supportedWorkloadFamilies"));
        Assert.DoesNotContain("quicTransport", ReadYamlList(implementationYaml, "capabilities"));
        Assert.DoesNotContain("quic.transport.", implementationYaml);
    }

    [Fact]
    public void Raw_quic_package_builder_uses_quic_dotnet_owned_projects()
    {
        var repoRoot = FindRepoRoot();
        var builderScript = File.ReadAllText(Path.Combine(repoRoot, "eng", "protocol-lab", "New-QuicDotNetProtocolLabPackage.ps1"));
        Assert.Contains("eng/protocol-lab/src/Incursa.ProtocolLab.Adapters.IncursaRawQuic/Incursa.ProtocolLab.Adapters.IncursaRawQuic.csproj", builderScript);
        Assert.Contains("eng/protocol-lab/servers/IncursaRawQuicServer/IncursaRawQuicServer.csproj", builderScript);
        Assert.Contains("UseProtocolLabContracts", builderScript);
        Assert.Contains("under the quic-dotnet root", builderScript);
        Assert.Contains("Assert-PathUnderRoot", builderScript);
        Assert.Contains("Test-NoRestoreRuntimeAssetFailure", builderScript);
        Assert.Contains("Rerun the package build once without -NoRestore", builderScript);
        Assert.Contains("Invoke-GitValue", builderScript);
        Assert.Contains("$executionManifest.sourceRepository = $sourceRepository", builderScript);
        Assert.Contains("$executionManifest.sourceCommit = $sourceCommit", builderScript);
        Assert.Contains("Remove-Item -LiteralPath $publishRoot", builderScript);
        Assert.Contains("Join-Path $PSScriptRoot \"..\\..\"", builderScript);
        Assert.DoesNotContain("(Get-Location).Path", builderScript, StringComparison.Ordinal);
        Assert.DoesNotContain("$manifest.environments = @($executionManifest.environments)", builderScript);
        Assert.DoesNotContain("$manifest.dependencies = $executionManifest.dependencies", builderScript);
        Assert.Contains("$executionManifest.environments = @(", builderScript);
        Assert.Contains("$executionManifest.dependencies.requiresDotNet", builderScript);
        Assert.DoesNotContain("@($RepoRoot, $ProtocolLabRoot)", builderScript, StringComparison.Ordinal);

        Assert.True(File.Exists(Path.Combine(repoRoot, "eng", "protocol-lab", "src", "Incursa.ProtocolLab.Adapters.IncursaRawQuic", "Incursa.ProtocolLab.Adapters.IncursaRawQuic.csproj")));
        Assert.True(File.Exists(Path.Combine(repoRoot, "eng", "protocol-lab", "servers", "IncursaRawQuicServer", "IncursaRawQuicServer.csproj")));
    }

    [Fact]
    public void Raw_quic_adapter_project_uses_public_contracts_not_public_adapters()
    {
        var repoRoot = FindRepoRoot();
        var projectPath = Path.Combine(repoRoot, "eng", "protocol-lab", "src", "Incursa.ProtocolLab.Adapters.IncursaRawQuic", "Incursa.ProtocolLab.Adapters.IncursaRawQuic.csproj");
        var document = XDocument.Load(projectPath);
        var projectReferences = document.Descendants("ProjectReference")
            .Select(element => element.Attribute("Include")?.Value ?? "")
            .ToArray();

        var packageReferences = document.Descendants("PackageReference")
            .Select(element => element.Attribute("Include")?.Value ?? "")
            .ToArray();

        Assert.Contains("Incursa.ProtocolLab.Adapter.Contracts", packageReferences);
        Assert.Contains("Incursa.ProtocolLab.Model", packageReferences);
        Assert.Contains(@"..\..\servers\IncursaRawQuicServer\IncursaRawQuicServer.csproj", projectReferences);
        Assert.DoesNotContain(projectReferences, value =>
            value.Contains(@"$(ProtocolLabRoot)\src\Incursa.ProtocolLab.", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(projectReferences, value =>
            value.Contains(@"$(ProtocolLabRoot)\src\Incursa.ProtocolLab.Adapters.", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Raw_quic_server_project_stays_transport_only()
    {
        var repoRoot = FindRepoRoot();
        var projectPath = Path.Combine(repoRoot, "eng", "protocol-lab", "servers", "IncursaRawQuicServer", "IncursaRawQuicServer.csproj");
        var document = XDocument.Load(projectPath);
        var projectReferences = document.Descendants("ProjectReference")
            .Select(element => element.Attribute("Include")?.Value ?? "")
            .ToArray();
        var source = File.ReadAllText(Path.Combine(repoRoot, "eng", "protocol-lab", "servers", "IncursaRawQuicServer", "Program.cs"));

        Assert.Contains(@"$(IncursaQuicSourceRoot)\src\Incursa.Quic\Incursa.Quic.csproj", projectReferences);
        Assert.DoesNotContain(projectReferences, value => value.Contains("Incursa.Quic.Http3", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(projectReferences, value => value.Contains("Incursa.Quic.Qlog", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(projectReferences, value => value.Contains("Incursa.Qpack", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain("Incursa.Quic.Qlog", source);
        Assert.DoesNotContain("QuicQlogCapture", source);
        Assert.DoesNotContain("PROTOCOL_LAB_INCURSA_RAW_QUIC_QLOG_PATH", source);
        Assert.Contains("TryAcceptInboundStreamAsync", source);
        Assert.Contains("TryReadTerminalAsync", source);
        Assert.DoesNotContain("connection.AcceptInboundStreamAsync", source);
        Assert.DoesNotContain("stream.ReadAsync(buffer.AsMemory", source);
    }

    [Fact]
    public void Http3_client_peer_stream_observer_uses_terminal_safe_internal_paths()
    {
        var repoRoot = FindRepoRoot();
        var source = File.ReadAllText(Path.Combine(repoRoot, "src", "Incursa.Quic.Http3", "Http3Client.cs"));
        var observerStart = source.IndexOf(
            "private async Task ObservePeerUnidirectionalStreamsAsync",
            StringComparison.Ordinal);
        var observerEnd = source.IndexOf(
            "private async Task RejectPeerBidirectionalStreamAsync",
            StringComparison.Ordinal);

        Assert.True(observerStart >= 0);
        Assert.True(observerEnd > observerStart);

        var observerSource = source[observerStart..observerEnd];
        Assert.Contains("TryAcceptInboundStreamAsync", observerSource);
        Assert.DoesNotContain("connection.AcceptInboundStreamAsync", observerSource);
        Assert.DoesNotContain("ReadAsync", observerSource);
        Assert.Contains("TryReadTerminalAsync", source);
    }

    [Fact]
    public void Run_helper_submits_raw_quic_component_package_references()
    {
        var repoRoot = FindRepoRoot();
        var helperScript = File.ReadAllText(Path.Combine(repoRoot, "eng", "protocol-lab", "Invoke-QuicDotNetProtocolLabRun.ps1"));

        Assert.Contains("Assert-RunSelection", helperScript);
        Assert.Contains("TestExecutorId = \"quic-go-raw-load\"", helperScript);
        Assert.Contains("-TestExecutorId", helperScript);
        Assert.Contains("SupportedScenarioIds", helperScript);
        Assert.Contains("quic.transport.stream-throughput.1mb", helperScript);
        Assert.Contains("quic.transport.multiplex.100x64kb", helperScript);
        Assert.Contains("quic.transport.duplex-streams", helperScript);
        Assert.Contains("New-ProtocolLabRawQuicComponentPackages.ps1", helperScript);
        Assert.Contains("New-ProtocolLabH3ComponentPackages.ps1", helperScript);
        Assert.Contains("Package-backed raw QUIC jobs require package-provided scenario and test-executor inventory", helperScript);
        Assert.Contains("Package-backed H3 jobs require package-provided scenario and test-executor inventory", helperScript);
        Assert.Contains("set -ProtocolLabExecutionRoot to protocol-lab-internal", helperScript);
        Assert.DoesNotContain("Continuing with the implementation package and the worker catalog", helperScript);
        Assert.Contains("ProtocolLabExecutionRoot", helperScript);
        Assert.Contains("PROTOCOL_LAB_EXECUTION_ROOT", helperScript);
        Assert.Contains("$protocolLabExecutionRootFullPath", helperScript);
        Assert.Contains("protocolLabExecutionRoot = $protocolLabExecutionRootFullPath", helperScript);
        Assert.Contains("h3-large-body-v1", helperScript);
        Assert.Contains("http3.payload.bytes.1kb", helperScript);
        Assert.Contains("http3.payload.bytes.64kb", helperScript);
        Assert.Contains("http3.payload.bytes.1mb", helperScript);
        Assert.Contains("h3-small-payload-c32", helperScript);
        Assert.Contains("h3-small-payload-c128", helperScript);
        Assert.Contains("($ScenarioId -join \",\")", helperScript);
        Assert.Contains("SourceBackedTestExecutor", helperScript);
        Assert.Contains("packageReferences", helperScript);
        Assert.Contains("$componentPackageReferences = @($componentPackageResult.packageReferences)", helperScript);
        Assert.Contains("$componentPackagePaths = @(", helperScript);
        Assert.Contains("Upload-LabPackage", helperScript);
        Assert.Contains("Invoke-ControllerJson", helperScript);
        Assert.Contains("Wait-LabJob", helperScript);
        Assert.Contains("[int] $Repetitions", helperScript);
        Assert.Contains("$jobRequest.repetitions = $Repetitions", helperScript);
        Assert.Contains("[switch] $CaptureCounters", helperScript);
        Assert.Contains("[switch] $CaptureTrace", helperScript);
        Assert.Contains("$jobRequest.extensions.captureCounters = $true", helperScript);
        Assert.Contains("$jobRequest.extensions.captureTrace = $true", helperScript);
        Assert.Contains("$allPackageReferences = @()", helperScript);
        Assert.Contains("$allPackageReferences += @($PackageReference", helperScript);
        Assert.Contains("packages = $allPackageReferences", helperScript);
        Assert.Contains("ConvertFrom-PackageReferenceString", helperScript);
        Assert.Contains("packageId|packageVersion|sha256", helperScript);
        Assert.Contains("componentPackages = $componentPackageResult", helperScript);
    }

    [Theory]
    [InlineData("h3", "quic.transport.multiplex.100x64kb", "only supports protocol 'quic'")]
    [InlineData("quic", "http1.core.plaintext", "scenario(s) are not declared by the package template")]
    [InlineData("quic", "quic.transport.handshake-cold", "scenario(s) are not declared by the package template")]
    public void Run_helper_rejects_raw_quic_h3_fallback_arguments(string protocol, string scenarioId, string expectedError)
    {
        var repoRoot = FindRepoRoot();
        var helperScript = Path.Combine(repoRoot, "eng", "protocol-lab", "Invoke-QuicDotNetProtocolLabRun.ps1");
        var result = RunPowerShellFile(
            helperScript,
            "-ControllerUri",
            "http://127.0.0.1:1",
            "-PackageTarget",
            "RawQuic",
            "-ProtocolLabRoot",
            repoRoot,
            "-SuiteId",
            "quic-transport-v1-comparison",
            "-ScenarioId",
            scenarioId,
            "-Protocol",
            protocol);

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains(expectedError, result.Output);
        Assert.DoesNotContain("Submit-ProtocolLabPackageRun.ps1", result.Output);
        Assert.DoesNotContain("managed-httpclient-h3-load", result.Output);
    }

    [Fact]
    public void Run_helper_rejects_raw_quic_h3_test_executor_arguments()
    {
        var repoRoot = FindRepoRoot();
        var helperScript = Path.Combine(repoRoot, "eng", "protocol-lab", "Invoke-QuicDotNetProtocolLabRun.ps1");
        var result = RunPowerShellFile(
            helperScript,
            "-ControllerUri",
            "http://127.0.0.1:1",
            "-PackageTarget",
            "RawQuic",
            "-ProtocolLabRoot",
            repoRoot,
            "-TestExecutorId",
            "managed-httpclient-h3-load");

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("only supports test executor 'quic-go-raw-load'", result.Output);
        Assert.DoesNotContain("Submit-ProtocolLabPackageRun.ps1", result.Output);
    }

    [Theory]
    [InlineData("h3-large-body-v1", "http3.payload.stream.100x16kb", "scenario(s) are not declared by the package template")]
    [InlineData("h3-large-body-v1", "quic.transport.multiplex.100x64kb", "scenario(s) are not declared by the package template")]
    [InlineData("quic-transport-v1-comparison", "http3.payload.bytes.1kb", "only supports suite(s): h3-local-v1, h3-large-body-v1")]
    public void Run_helper_rejects_http3_undeclared_package_arguments(string suiteId, string scenarioId, string expectedError)
    {
        var repoRoot = FindRepoRoot();
        var protocolLabRoot = Path.GetFullPath(Path.Combine(repoRoot, "..", "protocol-lab"));
        var helperScript = Path.Combine(repoRoot, "eng", "protocol-lab", "Invoke-QuicDotNetProtocolLabRun.ps1");
        var result = RunPowerShellFile(
            helperScript,
            "-ControllerUri",
            "http://127.0.0.1:1",
            "-PackageTarget",
            "Http3",
            "-ProtocolLabRoot",
            protocolLabRoot,
            "-SuiteId",
            suiteId,
            "-ScenarioId",
            scenarioId,
            "-Protocol",
            "h3",
            "-TestExecutorId",
            "managed-httpclient-h3-load");

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains(expectedError, result.Output);
        Assert.DoesNotContain("Submit-ProtocolLabPackageRun.ps1", result.Output);
        Assert.DoesNotContain("New-QuicDotNetProtocolLabPackage.ps1", result.Output);
    }

    [Fact]
    public void Agent_guidance_names_package_v2_contract()
    {
        var repoRoot = FindRepoRoot();
        var agentGuidance = File.ReadAllText(Path.Combine(repoRoot, "AGENTS.md"));

        Assert.Contains("schemaVersion: protocol-lab-package-v2", agentGuidance);
        Assert.DoesNotContain("schemaVersion: protocol-lab-package-v1", agentGuidance);
    }

    [Fact]
    public void Readiness_evidence_script_records_packages_hashes_runner_and_external_blockers()
    {
        var repoRoot = FindRepoRoot();
        var scriptPath = Path.Combine(repoRoot, "scripts", "perf", "New-QuicProtocolLabReadinessEvidence.ps1");
        var script = File.ReadAllText(scriptPath);
        var readme = File.ReadAllText(Path.Combine(repoRoot, "scripts", "perf", "README.md"));

        Assert.Contains("quic-dotnet-protocol-lab-readiness-v2", script);
        Assert.Contains("New-QuicDotNetProtocolLabPackage.ps1", script);
        Assert.Contains("PackageTarget", script);
        Assert.Contains("Http3", script);
        Assert.Contains("RawQuic", script);
        Assert.Contains("Get-FileHash", script);
        Assert.Contains("SHA-256", script);
        Assert.Contains("ProtocolLabRunRoot", script);
        Assert.Contains("LabControllerEvidencePath", script);
        Assert.Contains("labControllerEvidence", script);
        Assert.Contains("Lab Controller Topology Evidence", script);
        Assert.Contains("evidenceClassDefinitions", script);
        Assert.Contains("local-lab", script);
        Assert.Contains("isolated-local", script);
        Assert.Contains("external-reference", script);
        Assert.Contains("publishable", script);
        Assert.Contains("MinimumPublishableRepetitions", script);
        Assert.Contains("LocalMaxRelativeRange", script);
        Assert.Contains("PublishableMaxRelativeRange", script);
        Assert.Contains("checksumInventory", script);
        Assert.Contains("ComponentPackageDirectory", script);
        Assert.Contains("PROTOCOL_LAB_COMPONENT_PACKAGE_DIRECTORY", script);
        Assert.Contains("componentPackageEvidence", script);
        Assert.Contains("Component Package Evidence", script);
        Assert.Contains("Get-ComponentPackageEvidence", script);
        Assert.Contains("publishableRunbook", script);
        Assert.Contains("isolatedLocalUpgradeRequirements", script);
        Assert.Contains("readinessProofCommandTemplate", script);
        Assert.Contains("repeat-count-below-publishable-minimum", script);
        Assert.Contains("environmentGates", script);
        Assert.Contains("measuredTopology", script);
        Assert.Contains("attestations", script);
        Assert.Contains("isolatedLocalRequirements", script);
        Assert.Contains("separate-target-and-load-generator-host", script);
        Assert.Contains("non-loopback-network-path", script);
        Assert.Contains("cpu-isolation-or-reservation-attestation", script);
        Assert.Contains("same-host-loopback-target-and-load-generator", script);
        Assert.Contains("cpu-isolation-unattested-local-process", script);
        Assert.Contains("network-isolation-unattested-loopback", script);
        Assert.Contains("load-generator-process-telemetry-unavailable", script);
        Assert.Contains("http3-local-live-current", script);
        Assert.Contains("runner-report.json", script);
        Assert.Contains("Raw QUIC multiplex smoke", script);
        Assert.Contains("Raw QUIC duplex smoke", script);
        Assert.Contains("Package-backed HTTP/3 rack lab smoke", script);
        Assert.Contains("Package-backed raw QUIC rack lab smoke", script);
        Assert.Contains("local-source-reference", script);
        Assert.Contains("package-backed-controller", script);
        Assert.Contains("live DNSSEC chain validation", script);
        Assert.Contains("DNS provider publication", script);
        Assert.Contains("IKEv2/IPsec session integration", script);
        Assert.Contains("host resolver application", script);
        Assert.Contains("DHCP and Router Advertisement emission", script);
        Assert.Contains("live encrypted DNS establishment", script);
        Assert.Contains("readiness-manifest.json", script);
        Assert.Contains("protocolLabPrerequisites", script);
        Assert.Contains("protocolLabExecutionRoot", script);
        Assert.Contains("PROTOCOL_LAB_EXECUTION_ROOT", script);
        Assert.Contains("scripts\\benchmarking\\Invoke-ProtocolLabBenchmarkSet.ps1", script);

        Assert.Contains("ProtocolLab Readiness Evidence", readme);
        Assert.Contains("New-QuicProtocolLabReadinessEvidence.ps1", readme);
        Assert.Contains("credential, authority", readme);
        Assert.Contains("publishable benchmark evidence", readme);
        Assert.Contains("isolated-local gate status", readme);
    }

    [Fact]
    public void Readiness_evidence_script_summarizes_protocol_lab_runs_and_quality_gates()
    {
        var repoRoot = FindRepoRoot();
        var temporaryRoot = Path.Combine(Path.GetTempPath(), "quic-readiness-test-" + Guid.NewGuid().ToString("N"));
        var contractRoot = Path.Combine(temporaryRoot, "protocol-lab");
        var executionRoot = Path.Combine(temporaryRoot, "protocol-lab-internal");
        var benchmarkScriptDirectory = Path.Combine(executionRoot, "scripts", "benchmarking");
        var componentPackageDirectory = Path.Combine(temporaryRoot, "protocol-lab-components", "artifacts", "packages");
        var runRoot = Path.Combine(temporaryRoot, "runs", "local-repeat");
        var missingAggregateRunRoot = Path.Combine(temporaryRoot, "runs", "missing-aggregate");
        var outputRoot = Path.Combine(temporaryRoot, "readiness");
        var labControllerEvidencePath = Path.Combine(temporaryRoot, "lab-controller-evidence.json");

        Directory.CreateDirectory(contractRoot);
        Directory.CreateDirectory(benchmarkScriptDirectory);
        Directory.CreateDirectory(componentPackageDirectory);
        Directory.CreateDirectory(runRoot);
        Directory.CreateDirectory(missingAggregateRunRoot);
        File.WriteAllText(Path.Combine(executionRoot, "Incursa.ProtocolLab.sln"), "");
        File.WriteAllText(Path.Combine(benchmarkScriptDirectory, "Invoke-ProtocolLabBenchmarkSet.ps1"), "");
        CreateComponentPackage(
            Path.Combine(componentPackageDirectory, "org.protocol-lab.components.executor.quic-go-raw-load.0.1.0.win-x64.plabpkg"),
            "org.protocol-lab.components.executor.quic-go-raw-load",
            "0.1.0",
            "test-executor");
        File.WriteAllText(Path.Combine(runRoot, "summary.md"), "# Synthetic run");
        File.WriteAllText(Path.Combine(runRoot, "run.json"), "{}");
        File.WriteAllText(Path.Combine(runRoot, "evidence-report.json"), "{}");
        File.WriteAllText(Path.Combine(runRoot, "telemetry-bundle.json"), "{}");
        File.WriteAllText(Path.Combine(runRoot, "aggregate-results.json"), """
            {
              "runId": "local-repeat",
              "generatedAt": "2026-06-17T12:00:00+00:00",
              "metadata": {
                "hostName": "test-host",
                "operatingSystem": "Windows",
                "frameworkDescription": ".NET 10.0.0",
                "processorCount": 8,
                "executionProfile": "localProcess"
              },
              "totals": {
                "validation": { "passed": 3, "failed": 0, "unsupported": 0, "notApplicable": 0, "inconclusive": 0, "infrastructureFailure": 0 }
              },
              "aggregates": [
                {
                  "implementationId": "quic-dotnet-raw-dev",
                  "scenarioId": "quic.transport.multiplex.100x64kb",
                  "protocol": "quic",
                  "executionProfile": "local-process",
                  "loadProfileId": "local-comparison",
                  "loadTool": "quic-go-raw-load",
                  "loadToolMode": "process",
                  "loadToolCategory": "managed-lab",
                  "targetExecutionMode": "process",
                  "targetProcessMetricsCapturedCount": 0,
                  "targetProcessMetricsMissingCount": 3,
                  "loadToolDockerMetricsCapturedCount": 0,
                  "loadToolDockerMetricsMissingCount": 0,
                  "loadToolProcessMetricsCapturedCount": 3,
                  "loadToolProcessMetricsMissingCount": 0,
                  "repetitions": 3,
                  "validation": { "passed": 3, "failed": 0, "unsupported": 0, "notApplicable": 0, "inconclusive": 0, "infrastructureFailure": 0 },
                  "failedRequests": 0,
                  "timeoutRequests": 0,
                  "warnings": [
                    "Target URL is localhost; client and server share host resources.",
                    "load-generator-process-metrics-captured",
                    "single-machine",
                    "no-cpu-isolation",
                    "no-network-isolation"
                  ],
                  "evidence": {
                    "evidenceClass": "local-lab",
                    "comparabilityStatus": "comparable-with-warnings",
                    "comparabilityWarnings": ["single-machine"]
                  },
                  "requestsPerSecond": { "median": 100.0, "best": 103.0, "worst": 98.0 },
                  "latencyMeanMs": { "median": 10.0, "best": 9.8, "worst": 10.2 },
                  "throughputBytesPerSecond": { "median": 6553600.0, "best": 6750208.0, "worst": 6422528.0 }
                }
              ],
              "claimLevel": "validation"
            }
            """);
        File.WriteAllText(labControllerEvidencePath, """
            {
              "controllerUrl": "http://10.10.99.176:5088",
              "capturedUtc": "2026-06-20T00:00:00Z",
              "nodes": [
                {
                  "nodeId": "plab-worker-sut-01",
                  "status": "Ready",
                  "labels": {
                    "role": "sut",
                    "workerKind": "server-under-test",
                    "host": "r920",
                    "evidenceTier": "lab-vm-single-host",
                    "benchmarkAddress": "10.50.0.11"
                  }
                },
                {
                  "nodeId": "plab-worker-load-01",
                  "status": "Ready",
                  "labels": {
                    "role": "load",
                    "workerKind": "load-generator",
                    "host": "r920",
                    "evidenceTier": "lab-vm-single-host",
                    "benchmarkAddress": "10.50.0.12"
                  }
                }
              ],
              "isolatedPairPreview": {
                "canSubmit": true,
                "blockers": [],
                "roles": [
                  { "name": "sut", "matchedNodeIds": [ "plab-worker-sut-01" ] },
                  { "name": "load", "matchedNodeIds": [ "plab-worker-load-01" ] }
                ]
              }
            }
            """);

        try
        {
            var scriptPath = Path.Combine(repoRoot, "scripts", "perf", "New-QuicProtocolLabReadinessEvidence.ps1");
            var result = RunPowerShellFile(
                scriptPath,
                "-ProtocolLabRoot",
                contractRoot,
                "-ProtocolLabExecutionRoot",
                executionRoot,
                "-ComponentPackageDirectory",
                componentPackageDirectory,
                "-ComponentPackage",
                "org.protocol-lab.components.executor.quic-go-raw-load",
                "-OutputRoot",
                outputRoot,
                "-RunId",
                "test-readiness",
                "-SkipPackageBuild",
                "-ProtocolLabRunRoot",
                runRoot,
                "-LabControllerEvidencePath",
                labControllerEvidencePath);

            Assert.Equal(0, result.ExitCode);

            var manifestPath = Path.Combine(outputRoot, "test-readiness", "readiness-manifest.json");
            using var document = JsonDocument.Parse(File.ReadAllText(manifestPath));
            var root = document.RootElement;

            Assert.Equal("quic-dotnet-protocol-lab-readiness-v2", root.GetProperty("schemaVersion").GetString());
            var componentEvidence = root.GetProperty("componentPackageEvidence");
            Assert.True(componentEvidence.GetProperty("present").GetBoolean());
            var componentPackage = Assert.Single(componentEvidence.GetProperty("packages").EnumerateArray());
            Assert.Equal("org.protocol-lab.components.executor.quic-go-raw-load", componentPackage.GetProperty("packageId").GetString());
            Assert.Equal("0.1.0", componentPackage.GetProperty("packageVersion").GetString());
            Assert.Equal(64, componentPackage.GetProperty("sha256").GetString()!.Length);
            var labControllerEvidence = root.GetProperty("labControllerEvidence");
            Assert.True(labControllerEvidence.GetProperty("present").GetBoolean());
            Assert.Equal("http://10.10.99.176:5088", labControllerEvidence.GetProperty("controllerUrl").GetString());
            Assert.Equal(64, labControllerEvidence.GetProperty("sha256").GetString()!.Length);
            var labControllerSummary = labControllerEvidence.GetProperty("summary");
            Assert.Equal(2, labControllerSummary.GetProperty("nodeCount").GetInt32());
            Assert.True(labControllerSummary.GetProperty("separateRolesAvailable").GetBoolean());
            Assert.True(labControllerSummary.GetProperty("samePhysicalHostObserved").GetBoolean());
            Assert.Contains(
                labControllerSummary.GetProperty("blockers").EnumerateArray(),
                blocker => blocker.GetString() == "physical-host-isolation-unattested:r920");
            Assert.True(labControllerSummary.GetProperty("isolatedPairPreview").GetProperty("canSubmit").GetBoolean());
            Assert.Equal("local-lab", root.GetProperty("readinessQuality").GetProperty("evidenceClass").GetString());
            Assert.Equal("blocked", root.GetProperty("readinessQuality").GetProperty("publishability").GetProperty("status").GetString());
            Assert.Contains(
                root.GetProperty("readinessQuality").GetProperty("publishability").GetProperty("blockers").EnumerateArray(),
                blocker => blocker.GetString() == "overall-evidence-class-is-local-lab");
            Assert.DoesNotContain(
                root.GetProperty("readinessQuality").GetProperty("publishability").GetProperty("blockers").EnumerateArray(),
                blocker => blocker.GetString() == "load-generator-process-telemetry-unavailable");

            var run = Assert.Single(root.GetProperty("protocolLabRuns").EnumerateArray());
            Assert.Equal("local-repeat", run.GetProperty("runId").GetString());
            Assert.Equal("local-lab", run.GetProperty("evidenceClass").GetString());
            Assert.True(run.GetProperty("checksumInventoryCount").GetInt32() >= 4);

            var cell = Assert.Single(run.GetProperty("cellReadiness").EnumerateArray());
            Assert.Equal("passed", cell.GetProperty("qualityGate").GetProperty("localStatus").GetString());
            Assert.Equal("none", cell.GetProperty("qualityGate").GetProperty("failureClass").GetString());
            Assert.Equal(3, cell.GetProperty("qualityGate").GetProperty("repetitions").GetInt32());
            Assert.Equal("blocked", cell.GetProperty("publishability").GetProperty("status").GetString());
            Assert.Contains(
                cell.GetProperty("publishability").GetProperty("blockers").EnumerateArray(),
                blocker => blocker.GetString() == "same-host-loopback-target-and-load-generator");
            Assert.DoesNotContain(
                cell.GetProperty("publishability").GetProperty("blockers").EnumerateArray(),
                blocker => blocker.GetString() == "shared-host-or-localhost");
            Assert.DoesNotContain(
                cell.GetProperty("publishability").GetProperty("blockers").EnumerateArray(),
                blocker => blocker.GetString() == "load-generator-process-telemetry-unavailable");
            var gates = cell.GetProperty("environmentGates");
            Assert.Equal("same-host-loopback", gates.GetProperty("hostClassification").GetProperty("status").GetString());
            Assert.Equal("not-proven", gates.GetProperty("cpuIsolation").GetProperty("status").GetString());
            Assert.Equal("not-proven", gates.GetProperty("networkIsolation").GetProperty("status").GetString());
            Assert.Equal("missing", gates.GetProperty("targetResourceMetrics").GetProperty("status").GetString());
            Assert.Equal("process-telemetry-captured", gates.GetProperty("loadGeneratorSaturation").GetProperty("status").GetString());
            Assert.Equal(3, gates.GetProperty("loadGeneratorSaturation").GetProperty("processMetricsCapturedCount").GetInt32());
            Assert.Equal("blocked", gates.GetProperty("isolatedLocalGate").GetProperty("status").GetString());

            var measuredTopology = gates.GetProperty("measuredTopology");
            Assert.Equal("measured", measuredTopology.GetProperty("hostCpuTopology").GetProperty("status").GetString());
            Assert.Equal("test-host", measuredTopology.GetProperty("hostCpuTopology").GetProperty("hostName").GetString());
            Assert.Equal(8, measuredTopology.GetProperty("hostCpuTopology").GetProperty("processorCount").GetInt32());
            Assert.Equal("not-attested", measuredTopology.GetProperty("hostCpuTopology").GetProperty("attestationStatus").GetString());
            Assert.Equal("same-host-observed", measuredTopology.GetProperty("processPlacement").GetProperty("status").GetString());
            Assert.False(measuredTopology.GetProperty("processPlacement").GetProperty("separateHostObserved").GetBoolean());
            Assert.True(measuredTopology.GetProperty("processPlacement").GetProperty("sameProcessNamespaceObserved").GetBoolean());
            Assert.Equal("loopback-observed", measuredTopology.GetProperty("networkPath").GetProperty("status").GetString());

            var attestations = gates.GetProperty("attestations");
            Assert.Equal("not-attested", attestations.GetProperty("cpuIsolation").GetProperty("status").GetString());
            Assert.Equal("not-attested", attestations.GetProperty("networkIsolation").GetProperty("status").GetString());
            Assert.Equal("not-attested", attestations.GetProperty("hostPlacement").GetProperty("status").GetString());
            Assert.Equal("local-lab", attestations.GetProperty("evidenceClass").GetProperty("current").GetString());
            Assert.Equal("isolated-local", attestations.GetProperty("evidenceClass").GetProperty("requiredForIsolatedLocal").GetString());

            var requirements = gates.GetProperty("isolatedLocalRequirements").EnumerateArray().ToArray();
            Assert.Contains(requirements, requirement =>
                requirement.GetProperty("requirement").GetString() == "separate-target-and-load-generator-host" &&
                requirement.GetProperty("status").GetString() == "blocked");
            Assert.Contains(requirements, requirement =>
                requirement.GetProperty("requirement").GetString() == "non-loopback-network-path" &&
                requirement.GetProperty("blocker").GetString() == "network-isolation-unattested-loopback");
            Assert.Contains(requirements, requirement =>
                requirement.GetProperty("requirement").GetString() == "cpu-isolation-or-reservation-attestation" &&
                requirement.GetProperty("blocker").GetString() == "cpu-isolation-unattested-local-process");
            Assert.Contains(requirements, requirement =>
                requirement.GetProperty("requirement").GetString() == "target-resource-telemetry-retained" &&
                requirement.GetProperty("status").GetString() == "blocked");
            Assert.Contains(requirements, requirement =>
                requirement.GetProperty("requirement").GetString() == "load-generator-telemetry-retained" &&
                requirement.GetProperty("status").GetString() == "satisfied");

            var runbook = root.GetProperty("publishableRunbook");
            Assert.Contains("TargetMode external", runbook.GetProperty("isolatedLocalCommandTemplate").GetString());
            Assert.Contains("New-QuicProtocolLabReadinessEvidence.ps1", runbook.GetProperty("readinessProofCommandTemplate").GetString());
            Assert.Contains(
                runbook.GetProperty("isolatedLocalUpgradeRequirements").EnumerateArray(),
                requirement => requirement.GetString()!.Contains("non-loopback SUT endpoint", StringComparison.Ordinal));

            var generatedReadme = File.ReadAllText(Path.Combine(outputRoot, "test-readiness", "README.md"));
            Assert.Contains("## Lab Controller Topology Evidence", generatedReadme);
            Assert.Contains("plab-worker-sut-01", generatedReadme);
            Assert.Contains("physical-host-isolation-unattested:r920", generatedReadme);
            Assert.Contains("## Isolated-Local Upgrade Runbook", generatedReadme);
            Assert.Contains("separate-target-and-load-generator-host", generatedReadme);
            Assert.Contains("Rerun readiness proof", generatedReadme);

            var missingResult = RunPowerShellFile(
                scriptPath,
                "-ProtocolLabRoot",
                contractRoot,
                "-ProtocolLabExecutionRoot",
                executionRoot,
                "-ComponentPackageDirectory",
                componentPackageDirectory,
                "-OutputRoot",
                outputRoot,
                "-RunId",
                "test-readiness-missing-aggregate",
                "-SkipPackageBuild",
                "-ProtocolLabRunRoot",
                missingAggregateRunRoot);

            Assert.Equal(0, missingResult.ExitCode);
            var missingManifestPath = Path.Combine(outputRoot, "test-readiness-missing-aggregate", "readiness-manifest.json");
            using var missingDocument = JsonDocument.Parse(File.ReadAllText(missingManifestPath));
            var missingRun = Assert.Single(missingDocument.RootElement.GetProperty("protocolLabRuns").EnumerateArray());
            Assert.False(missingRun.GetProperty("present").GetBoolean());
            Assert.Equal("aggregate-results.json was not found", missingRun.GetProperty("blocker").GetString());
            Assert.Equal("blocked", missingRun.GetProperty("publishability").GetProperty("status").GetString());
            Assert.Contains(
                missingRun.GetProperty("publishability").GetProperty("blockers").EnumerateArray(),
                blocker => blocker.GetString() == "aggregate-results-json-missing");
        }
        finally
        {
            if (Directory.Exists(temporaryRoot))
            {
                Directory.Delete(temporaryRoot, recursive: true);
            }
        }
    }

    [Fact]
    public void Performance_lane_preflights_protocol_lab_benchmark_script()
    {
        var repoRoot = FindRepoRoot();
        var script = File.ReadAllText(Path.Combine(repoRoot, "scripts", "perf", "Invoke-QuicPerformanceLane.ps1"));

        Assert.Contains("scripts\\benchmarking\\Invoke-ProtocolLabBenchmarkSet.ps1", script);
        Assert.Contains("ProtocolLabExecutionRoot", script);
        Assert.Contains("PROTOCOL_LAB_EXECUTION_ROOT", script);
        Assert.Contains("ProtocolLab benchmark set script was not found", script);
        Assert.Contains("Test-Path -LiteralPath $protocolLabBenchmarkScript -PathType Leaf", script);
        Assert.Contains("throw \"ProtocolLab benchmark set script was not found in execution root: $protocolLabBenchmarkScript\"", script);
        Assert.Contains("\"RawQuicStreamThroughput\"", script);
        Assert.Contains("quic.transport.stream-throughput.1mb", script);
        Assert.Contains("\"CryptoCore\"", script);
        Assert.Contains("*QuicTlsX25519Benchmarks*", script);
        Assert.Contains("BaselineAggregatePath", script);
        Assert.Contains("ExtremePrimaryMetricDropPercent", script);
        Assert.Contains("ExtremeLatencyIncreasePercent", script);
        Assert.Contains("extreme-metric-regression", script);
        Assert.Contains("performanceGate", script);
        Assert.Contains("FailOnPerformanceGate", script);
        Assert.Contains("Get-ObjectPropertyValue -Object $Aggregate -Name \"loadTool\"", script);
        Assert.DoesNotContain("loadTool = $Aggregate.loadTool", script);
    }

    [Fact]
    public void Performance_closeout_helper_preserves_traceability_sections()
    {
        var repoRoot = FindRepoRoot();
        var script = File.ReadAllText(Path.Combine(repoRoot, "scripts", "perf", "New-QuicPerformanceCloseout.ps1"));
        var readme = File.ReadAllText(Path.Combine(repoRoot, "scripts", "perf", "README.md"));

        Assert.Contains("incursa.quic.performance-closeout.v1", script);
        Assert.Contains("correctnessEvidence", script);
        Assert.Contains("performanceEvidence", script);
        Assert.Contains("RequirementHomeTestCommand", script);
        Assert.Contains("KnownSpecTraceBacklogNote", script);
        Assert.Contains("ProtocolLabArtifactPath", script);
        Assert.Contains("Performance Closeout Evidence", readme);
        Assert.Contains("New-QuicPerformanceCloseout.ps1", readme);
    }

    [Fact]
    public void Local_protocol_lab_benchmark_helper_resolves_internal_package_version_pins()
    {
        var repoRoot = FindRepoRoot();
        var script = File.ReadAllText(Path.Combine(repoRoot, "scripts", "perf", "Invoke-ProtocolLabLocalQuicBenchmark.ps1"));

        Assert.Contains("Directory.Packages.props", script);
        Assert.Contains("Directory.Build.props", script);
        Assert.Contains("IncursaQuicVersion", script);
        Assert.Contains("IncursaQpackVersion", script);
        Assert.Contains("IncursaQuicHttp3Version", script);
        Assert.Contains("ComponentPackageDirectory", script);
        Assert.Contains("-ComponentPackageDirectory", script);
        Assert.Contains("-ComponentPackageMaterializationRoot", script);
        Assert.Contains("Pass -PackageVersion explicitly or align package pins", script);
    }

    [Fact]
    public void Package_icon_metadata_is_conditional_on_asset_presence()
    {
        var repoRoot = FindRepoRoot();
        var props = File.ReadAllText(Path.Combine(repoRoot, "Directory.Build.props"));
        var targets = File.ReadAllText(Path.Combine(repoRoot, "Directory.Build.targets"));

        Assert.Contains("PackageIcon Condition=\"Exists('$(MSBuildThisFileDirectory)assets\\package-icon.png')\"", props);
        Assert.Contains("'$(IsPackable)' == 'true' And Exists('$(MSBuildThisFileDirectory)assets\\package-icon.png')", targets);
    }

    private static void AssertPackageEnvironment(JsonElement[] environments, string os, string arch)
    {
        var environment = Assert.Single(environments, value =>
            string.Equals(value.GetProperty("os").GetString(), os, StringComparison.Ordinal) &&
            string.Equals(value.GetProperty("arch").GetString(), arch, StringComparison.Ordinal));
        var entrypoint = environment.GetProperty("entrypoint");
        Assert.Equal("pwsh", entrypoint.GetProperty("kind").GetString());
        Assert.Equal("scripts/run-current-platform.ps1", entrypoint.GetProperty("path").GetString());
    }

    private static string[] ReadJsonStringArray(JsonElement root, string propertyName)
    {
        return root.GetProperty(propertyName)
            .EnumerateArray()
            .Select(value => value.GetString() ?? "")
            .Where(value => value.Length > 0)
            .ToArray();
    }

    private static string[] ReadYamlList(string yaml, string propertyName)
    {
        var lines = yaml.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');
        for (var index = 0; index < lines.Length; index++)
        {
            if (!string.Equals(lines[index], propertyName + ":", StringComparison.Ordinal))
            {
                continue;
            }

            var values = new List<string>();
            for (var valueIndex = index + 1; valueIndex < lines.Length; valueIndex++)
            {
                var line = lines[valueIndex];
                if (!line.StartsWith("  - ", StringComparison.Ordinal))
                {
                    break;
                }

                values.Add(line["  - ".Length..].Trim());
            }

            return values.ToArray();
        }

        return [];
    }

    private static ProcessResult RunPowerShell(params string[] arguments)
    {
        var startInfo = new ProcessStartInfo("pwsh")
        {
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            UseShellExecute = false,
        };

        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException("Failed to start pwsh.");
        var output = process.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();
        if (!process.WaitForExit(30_000))
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException("PowerShell script did not exit within 30 seconds.");
        }

        return new ProcessResult(process.ExitCode, output + error);
    }

    private static void CreateComponentPackage(string packagePath, string packageId, string packageVersion, string kind)
    {
        using var archive = ZipFile.Open(packagePath, ZipArchiveMode.Create);
        var manifest = JsonSerializer.Serialize(new
        {
            schemaVersion = "protocol-lab-package-v2",
            packageId,
            packageVersion,
            kind,
            displayName = packageId,
            entryManifests = new[] { "test-executors/fixture.yaml" },
        });
        AddZipEntry(archive, "protocol-lab-package.json", manifest);
        AddZipEntry(archive, "test-executors/fixture.yaml", "schemaVersion: protocol-lab-test-executor-v1");
    }

    private static void AddZipEntry(ZipArchive archive, string entryName, string content)
    {
        var entry = archive.CreateEntry(entryName);
        using var stream = entry.Open();
        using var writer = new StreamWriter(stream);
        writer.Write(content);
    }

    private static ProcessResult RunPowerShellFile(string scriptPath, params string[] arguments)
    {
        static string QuotePowerShellString(string value)
        {
            if (value.StartsWith("-", StringComparison.Ordinal) &&
                value.Length > 1 &&
                char.IsLetter(value[1]))
            {
                return value;
            }

            return "'" + value.Replace("'", "''", StringComparison.Ordinal) + "'";
        }

        var scriptInvocation = string.Join(
            " ",
            new[] { QuotePowerShellString(scriptPath) }.Concat(arguments.Select(QuotePowerShellString)));
        var command = $$"""
            $ErrorActionPreference = 'Stop'
            $ErrorView = 'NormalView'
            if (Get-Variable -Name PSStyle -ErrorAction SilentlyContinue) {
                $PSStyle.OutputRendering = 'PlainText'
            }

            try {
                & {{scriptInvocation}}
                exit $LASTEXITCODE
            }
            catch {
                [Console]::Error.WriteLine($_.Exception.Message)
                exit 1
            }
            """;

        var startInfo = new ProcessStartInfo("pwsh")
        {
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            UseShellExecute = false,
        };

        startInfo.ArgumentList.Add("-NoLogo");
        startInfo.ArgumentList.Add("-NoProfile");
        startInfo.ArgumentList.Add("-Command");
        startInfo.ArgumentList.Add(command);

        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException("Failed to start pwsh.");
        var output = process.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();
        if (!process.WaitForExit(30_000))
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException("PowerShell script did not exit within 30 seconds.");
        }

        return new ProcessResult(process.ExitCode, output + error);
    }

    private static string FindRepoRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "eng", "protocol-lab", "New-QuicDotNetProtocolLabPackage.ps1")) &&
                File.Exists(Path.Combine(directory.FullName, "Incursa.Quic.slnx")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("Could not locate quic-dotnet repository root.");
    }

    private sealed record ProcessResult(int ExitCode, string Output);
}
