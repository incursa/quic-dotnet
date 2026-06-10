// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Diagnostics;
using System.Text.Json;
using System.Xml.Linq;

namespace Incursa.Quic.Tests;

public sealed class ProtocolLabPackageTemplateTests
{
    private static readonly string[] RawQuicScenarioIds =
    [
        "quic.transport.multiplex.100x64kb",
        "quic.transport.duplex-streams",
    ];

    [Fact]
    public void Raw_quic_package_template_advertises_transport_contract()
    {
        var repoRoot = FindRepoRoot();
        var packageTemplatePath = Path.Combine(repoRoot, "eng", "protocol-lab", "templates", "raw-quic", "protocol-lab-package.json");
        var implementationTemplatePath = Path.Combine(repoRoot, "eng", "protocol-lab", "templates", "raw-quic", "implementations", "quic-dotnet-raw-dev.yaml");

        using var packageDocument = JsonDocument.Parse(File.ReadAllText(packageTemplatePath));
        var packageRoot = packageDocument.RootElement;
        Assert.Equal("protocol-lab-package-v2", packageRoot.GetProperty("schemaVersion").GetString());
        Assert.Equal("quic-dotnet-raw-dev", packageRoot.GetProperty("packageId").GetString());
        var providedImplementation = Assert.Single(packageRoot.GetProperty("providedImplementations").EnumerateArray());
        Assert.Equal("quic-dotnet-raw-dev", providedImplementation.GetProperty("implementationId").GetString());
        Assert.Equal(["quic"], ReadJsonStringArray(providedImplementation, "protocols"));
        Assert.Equal(RawQuicScenarioIds, ReadJsonStringArray(providedImplementation, "scenarios"));
        Assert.DoesNotContain("h3", ReadJsonStringArray(providedImplementation, "protocols"));
        Assert.DoesNotContain("http.core.plaintext", ReadJsonStringArray(providedImplementation, "scenarios"));
        Assert.False(packageRoot.TryGetProperty("supportedProtocols", out _));
        Assert.False(packageRoot.TryGetProperty("supportedWorkloadFamilies", out _));
        Assert.False(packageRoot.TryGetProperty("supportedScenarios", out _));
        Assert.False(packageRoot.TryGetProperty("capabilities", out _));
        var environments = packageRoot.GetProperty("environments").EnumerateArray().ToArray();
        Assert.Equal(2, environments.Length);
        AssertPackageEnvironment(environments, "linux", "x64");
        AssertPackageEnvironment(environments, "windows", "x64");
        var dependencies = packageRoot.GetProperty("dependencies");
        Assert.True(dependencies.GetProperty("requiresDotNet").GetBoolean());
        Assert.True(dependencies.GetProperty("requiresPwsh").GetBoolean());
        Assert.False(dependencies.GetProperty("requiresBash").GetBoolean());
        var runtimeRequirement = Assert.Single(dependencies.GetProperty("requiredCapabilities").EnumerateArray());
        Assert.Equal("libmsquic", runtimeRequirement.GetProperty("name").GetString());

        var implementationYaml = File.ReadAllText(implementationTemplatePath);
        Assert.Contains("id: quic-dotnet-raw-dev", implementationYaml);
        Assert.Contains("targetContract: adapter-v1", implementationYaml);
        Assert.Contains("executable: pwsh", implementationYaml);
        Assert.Contains("scripts/run-current-platform.ps1", implementationYaml);
        Assert.DoesNotContain("executable: bin/linux-x64/Incursa.ProtocolLab.Adapters.IncursaRawQuic", implementationYaml);
        Assert.Contains("IncursaRawQuicServer", implementationYaml);
        Assert.Contains("quic", ReadYamlList(implementationYaml, "supportedProtocols"));
        Assert.Contains("quic.transport", ReadYamlList(implementationYaml, "supportedWorkloadFamilies"));
        Assert.Contains("quic.transport.multiplex.100x64kb", ReadYamlList(implementationYaml, "supportedScenarios"));
        Assert.Contains("quic.transport.duplex-streams", ReadYamlList(implementationYaml, "supportedScenarios"));
        Assert.Equal(RawQuicScenarioIds, ReadYamlList(implementationYaml, "supportedScenarios"));
        Assert.DoesNotContain("h3", ReadYamlList(implementationYaml, "supportedProtocols"));
        Assert.DoesNotContain("http.application", ReadYamlList(implementationYaml, "supportedWorkloadFamilies"));
        Assert.DoesNotContain("http.core.", implementationYaml);
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
        var implementationTemplatePath = Path.Combine(repoRoot, "eng", "protocol-lab", "templates", "implementations", "quic-dotnet-dev.yaml");

        using var packageDocument = JsonDocument.Parse(File.ReadAllText(packageTemplatePath));
        Assert.Equal("protocol-lab-package-v2", packageDocument.RootElement.GetProperty("schemaVersion").GetString());
        Assert.Equal("quic-dotnet-dev", packageDocument.RootElement.GetProperty("packageId").GetString());
        var providedImplementation = Assert.Single(packageDocument.RootElement.GetProperty("providedImplementations").EnumerateArray());
        Assert.Equal("quic-dotnet-dev", providedImplementation.GetProperty("implementationId").GetString());
        Assert.Contains("h3", ReadJsonStringArray(providedImplementation, "protocols"));
        Assert.Contains("http.core.plaintext", ReadJsonStringArray(providedImplementation, "scenarios"));
        Assert.Contains("http.core.json", ReadJsonStringArray(providedImplementation, "scenarios"));

        var implementationYaml = File.ReadAllText(implementationTemplatePath);
        Assert.Contains("id: quic-dotnet-dev", implementationYaml);
        Assert.Contains("h3", ReadYamlList(implementationYaml, "supportedProtocols"));
        Assert.Contains("http.application", ReadYamlList(implementationYaml, "supportedWorkloadFamilies"));
        Assert.Contains("httpPlaintext", ReadYamlList(implementationYaml, "capabilities"));
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
        Assert.Contains("Remove-Item -LiteralPath $publishRoot", builderScript);
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

        Assert.Contains(@"$(ProtocolLabRoot)\src\Incursa.ProtocolLab.Adapter.Contracts\Incursa.ProtocolLab.Adapter.Contracts.csproj", projectReferences);
        Assert.Contains(@"$(ProtocolLabRoot)\src\Incursa.ProtocolLab.Model\Incursa.ProtocolLab.Model.csproj", projectReferences);
        Assert.Contains(@"..\..\servers\IncursaRawQuicServer\IncursaRawQuicServer.csproj", projectReferences);
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
        Assert.Contains("quic.transport.multiplex.100x64kb", helperScript);
        Assert.Contains("quic.transport.duplex-streams", helperScript);
        Assert.Contains("New-ProtocolLabRawQuicComponentPackages.ps1", helperScript);
        Assert.Contains("SourceBackedTestExecutor", helperScript);
        Assert.Contains("packageReferences", helperScript);
        Assert.Contains("$componentPackageReferences = @($componentPackageResult.packageReferences)", helperScript);
        Assert.Contains("$componentPackagePaths = @(", helperScript);
        Assert.Contains("@(\"-AdditionalPackagePath\") + $componentPackagePaths", helperScript);
        Assert.Contains("$allPackageReferences = @($PackageReference)", helperScript);
        Assert.Contains("@(\"-PackageReference\") + $allPackageReferences", helperScript);
        Assert.Contains("componentPackages = $componentPackageResult", helperScript);
    }

    [Theory]
    [InlineData("h3", "quic.transport.multiplex.100x64kb", "only supports protocol 'quic'")]
    [InlineData("quic", "http.core.plaintext", "scenario(s) are not declared by the package template")]
    [InlineData("quic", "quic.transport.handshake-cold", "scenario(s) are not declared by the package template")]
    public void Run_helper_rejects_raw_quic_h3_fallback_arguments(string protocol, string scenarioId, string expectedError)
    {
        var repoRoot = FindRepoRoot();
        var helperScript = Path.Combine(repoRoot, "eng", "protocol-lab", "Invoke-QuicDotNetProtocolLabRun.ps1");
        var result = RunPowerShell(
            "-NoLogo",
            "-NoProfile",
            "-File",
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
        var result = RunPowerShell(
            "-NoLogo",
            "-NoProfile",
            "-File",
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

    [Fact]
    public void Agent_guidance_names_package_v2_contract()
    {
        var repoRoot = FindRepoRoot();
        var agentGuidance = File.ReadAllText(Path.Combine(repoRoot, "AGENTS.md"));

        Assert.Contains("schemaVersion: protocol-lab-package-v2", agentGuidance);
        Assert.DoesNotContain("schemaVersion: protocol-lab-package-v1", agentGuidance);
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
