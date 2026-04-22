using System;
using System.IO;

namespace Incursa.Quic.Tests;

public sealed class InteropHarnessPackagingTests
{
    [Fact]
    public void DockerfileRestoresPublishesAndStagesTheInteropHarness()
    {
        string dockerfile = ReadNormalizedText("src/Incursa.Quic.InteropHarness/Dockerfile").TrimEnd();
        Assert.Contains("FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build", dockerfile, StringComparison.Ordinal);
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
    public void RunEndpointScriptUsesAStableShellContract()
    {
        string script = ReadNormalizedText("src/Incursa.Quic.InteropHarness/run_endpoint.sh").TrimEnd();
        Assert.StartsWith("#!/usr/bin/env bash\nset -euo pipefail", script, StringComparison.Ordinal);
        Assert.Contains("\"$SCRIPT_DIR/setup.sh\"", script, StringComparison.Ordinal);
        Assert.Contains("if [[ \"${ROLE:-}\" == \"client\" ]]; then", script, StringComparison.Ordinal);
        Assert.Contains("exec 3<>/dev/tcp/sim/57832", script, StringComparison.Ordinal);
        Assert.EndsWith("exec dotnet \"$SCRIPT_DIR/Incursa.Quic.InteropHarness.dll\" \"$@\"", script, StringComparison.Ordinal);
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
