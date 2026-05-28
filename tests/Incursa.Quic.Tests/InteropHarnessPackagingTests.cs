// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.IO;

namespace Incursa.Quic.Tests;

public sealed class InteropHarnessPackagingTests
{
    [Fact]
    public void DockerfileRestoresPublishesAndStagesTheInteropHarness()
    {
        string dockerfile = ReadNormalizedText("src/Incursa.Quic.InteropHarness/Dockerfile").TrimEnd();
        Assert.Contains("FROM mcr.microsoft.com/dotnet/sdk:10.0.201 AS build", dockerfile, StringComparison.Ordinal);
        Assert.Contains("RUN dotnet restore Incursa.Quic.slnx", dockerfile, StringComparison.Ordinal);
        Assert.Contains("RUN dotnet publish src/Incursa.Quic.InteropHarness/Incursa.Quic.InteropHarness.csproj -c Release -o /app/publish --no-restore", dockerfile, StringComparison.Ordinal);
        Assert.Contains("FROM mcr.microsoft.com/dotnet/runtime:10.0", dockerfile, StringComparison.Ordinal);
        Assert.Contains("apt-get install -y --no-install-recommends ethtool iproute2 net-tools", dockerfile, StringComparison.Ordinal);
        Assert.DoesNotContain("netcat-openbsd", dockerfile, StringComparison.Ordinal);
        Assert.Contains("COPY quic-dotnet/src/Incursa.Quic.InteropHarness/run_endpoint.sh /app/run_endpoint.sh", dockerfile, StringComparison.Ordinal);
        Assert.Contains("COPY quic-dotnet/src/Incursa.Quic.InteropHarness/setup.sh /app/setup.sh", dockerfile, StringComparison.Ordinal);
        Assert.Contains("RUN chmod +x /app/setup.sh", dockerfile, StringComparison.Ordinal);
        Assert.Contains("RUN chmod +x /app/run_endpoint.sh", dockerfile, StringComparison.Ordinal);
        Assert.Contains("ENTRYPOINT [\"/app/run_endpoint.sh\"]", dockerfile, StringComparison.Ordinal);
    }

    [Fact]
    public void InteropHelperShimRegistersVersionNegotiationWithTheUpstreamRunner()
    {
        string helper = ReadNormalizedText("scripts/interop/Invoke-QuicInteropRunner.ps1");
        Assert.Contains("TestCaseVersionNegotiation", helper, StringComparison.Ordinal);
        Assert.Contains("versionnegotiation", helper, StringComparison.Ordinal);
        Assert.Contains("TESTCASES_QUIC", helper, StringComparison.Ordinal);
    }

    [Fact]
    public void InteropHelperRegistersHttp3AsASupportedExecutedRunnerCell()
    {
        string helper = ReadNormalizedText("scripts/interop/Invoke-QuicInteropRunner.ps1");

        Assert.Contains("TestCase = 'http3'", helper, StringComparison.Ordinal);
        Assert.Contains("RunnerTestCase = 'http3'", helper, StringComparison.Ordinal);
        Assert.Contains("Classification = 'supported-executed'", helper, StringComparison.Ordinal);
    }

    [Fact]
    public void Http3InteropRunnerDocumentationContainsTheExactLocalCommand()
    {
        string docs = ReadNormalizedText("docs/interop-http3-runner.md");
        string interopReadme = ReadNormalizedText("scripts/interop/README.md");

        Assert.Contains("-TestCases http3", docs, StringComparison.Ordinal);
        Assert.Contains("-RunnerRoot C:\\src\\quic-interop\\quic-interop-runner", docs, StringComparison.Ordinal);
        Assert.Contains("-TestCases http3", interopReadme, StringComparison.Ordinal);
    }

    [Fact]
    public void Http3InteropRunnerWorkflowRunsTheLocalHttp3Cell()
    {
        string workflow = ReadNormalizedText(".github/workflows/interop-runner-http3.yml");

        Assert.Contains("Invoke-QuicInteropRunner.ps1", workflow, StringComparison.Ordinal);
        Assert.Contains("-TestCases http3", workflow, StringComparison.Ordinal);
        Assert.Contains("quic-interop-runner", workflow, StringComparison.Ordinal);
    }

    [Fact]
    public void InteropHelperShimPatchesPreferredAddressPathAnalysis()
    {
        string helper = ReadNormalizedText("scripts/interop/Invoke-QuicInteropRunner.ps1");

        Assert.Contains("_patched_testcase_inject_keylog_if_possible", helper, StringComparison.Ordinal);
        Assert.Contains("fd00:cafe:cafe:100::110", helper, StringComparison.Ordinal);
        Assert.Contains("trace.TraceAnalyzer._get_direction_filter = _patched_trace_direction_filter", helper, StringComparison.Ordinal);
        Assert.Contains("testcases_quic.TestCasePortRebinding.check = _patched_port_rebinding_check", helper, StringComparison.Ordinal);
        Assert.Contains("tr_server = self._server_trace()._get_packets(", helper, StringComparison.Ordinal);
        Assert.DoesNotContain("tr_server = self._client_trace()._get_packets(", helper, StringComparison.Ordinal);
        Assert.Contains("is_new_path = cur not in paths", helper, StringComparison.Ordinal);
    }

    [Fact]
    public void RunEndpointScriptUsesAStableShellContract()
    {
        string script = ReadNormalizedText("src/Incursa.Quic.InteropHarness/run_endpoint.sh").TrimEnd();
        Assert.StartsWith("#!/usr/bin/env bash\nset -euo pipefail", script, StringComparison.Ordinal);
        Assert.Contains("\"$SCRIPT_DIR/setup.sh\"", script, StringComparison.Ordinal);
        Assert.Contains("if [[ \"${ROLE:-}\" == \"client\" ]]; then", script, StringComparison.Ordinal);
        Assert.Contains("exec 3<>/dev/tcp/sim/57832", script, StringComparison.Ordinal);
        Assert.EndsWith("exec dotnet \"$SCRIPT_DIR/Incursa.Quic.InteropHarness.dll\" \"$@\"", script, StringComparison.Ordinal);
    }

    [Fact]
    public void SetupScriptClaimsTheConnectionMigrationPreferredAddressOnTheServer()
    {
        string script = ReadNormalizedText("src/Incursa.Quic.InteropHarness/setup.sh").TrimEnd();

        Assert.Contains("if [[ \"${ROLE:-}\" == \"server\" && \"${TESTCASE:-}\" == \"connectionmigration\" ]]; then", script, StringComparison.Ordinal);
        Assert.Contains("ip addr replace 193.167.100.110/32 dev eth0 preferred_lft 0", script, StringComparison.Ordinal);
        Assert.Contains("ip -6 addr replace fd00:cafe:cafe:100::110/128 dev eth0 preferred_lft 0", script, StringComparison.Ordinal);
    }

    private static string ReadNormalizedText(string relativePath)
    {
        string filePath = Path.Combine(FindRepoRoot(), relativePath);
        return File.ReadAllText(filePath).Replace("\r\n", "\n").Replace('\r', '\n');
    }

    private static string FindRepoRoot()
    {
        DirectoryInfo? current = new(AppContext.BaseDirectory);
        while (current is not null)
        {
            string candidate = Path.Combine(current.FullName, "src", "Incursa.Quic.InteropHarness", "Dockerfile");
            if (File.Exists(candidate))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Unable to locate the repository root for the interop packaging tests.");
    }
}
