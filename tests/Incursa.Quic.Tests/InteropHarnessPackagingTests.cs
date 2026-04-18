using System;
using System.IO;

namespace Incursa.Quic.Tests;

public sealed class InteropHarnessPackagingTests
{
    [Fact]
    public void DockerfileRestoresPublishesAndStagesTheInteropHarness()
    {
        string dockerfile = ReadNormalizedText("src/Incursa.Quic.InteropHarness/Dockerfile").TrimEnd();
        string expected = string.Join(
            '\n',
            [
                "FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build",
                "WORKDIR /src",
                "COPY quic-dotnet/ /src/",
                "RUN dotnet restore Incursa.Quic.slnx",
                "RUN dotnet publish src/Incursa.Quic.InteropHarness/Incursa.Quic.InteropHarness.csproj -c Release -o /app/publish --no-restore",
                "",
                "FROM mcr.microsoft.com/dotnet/runtime:10.0",
                "WORKDIR /app",
                "COPY --from=build /app/publish .",
                "COPY quic-dotnet/src/Incursa.Quic.InteropHarness/run_endpoint.sh /app/run_endpoint.sh",
                "RUN chmod +x /app/run_endpoint.sh",
                "ENTRYPOINT [\"/app/run_endpoint.sh\"]",
            ]);

        Assert.Equal(expected, dockerfile);
    }

    [Fact]
    public void RunEndpointScriptUsesAStableShellContract()
    {
        string script = ReadNormalizedText("src/Incursa.Quic.InteropHarness/run_endpoint.sh").TrimEnd();
        string expected = string.Join(
            '\n',
            [
                "#!/usr/bin/env sh",
                "set -eu",
                "",
                "SCRIPT_DIR=$(CDPATH= cd -- \"$(dirname -- \"$0\")\" && pwd)",
                "exec dotnet \"$SCRIPT_DIR/Incursa.Quic.InteropHarness.dll\" \"$@\"",
            ]);

        Assert.Equal(expected, script);
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
