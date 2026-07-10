// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class QuicPublicApiLifecyclePhaseBenchmarksTests
{
    [Fact]
    [Trait("Category", "Smoke")]
    public void LifecyclePhaseBenchmarkSurfaceIsRegisteredAndDocumented()
    {
        string benchmark = ReadRepositoryFile("benchmarks/QuicPublicApiLifecyclePhaseBenchmarks.cs");
        string readme = ReadRepositoryFile("benchmarks/README.md");
        string program = ReadRepositoryFile("benchmarks/Program.cs");

        Assert.Contains("public class QuicPublicApiLifecyclePhaseBenchmarks", benchmark, StringComparison.Ordinal);
        Assert.Contains("public enum QuicPublicApiLifecyclePhaseImplementation", benchmark, StringComparison.Ordinal);
        Assert.Contains("public enum QuicPublicApiLifecyclePhase", benchmark, StringComparison.Ordinal);
        Assert.Contains("public sealed record QuicPublicApiLifecyclePhaseBenchmarkCase", benchmark, StringComparison.Ordinal);
        Assert.Contains("ParamsSource(nameof(GetSupportedCases))", benchmark, StringComparison.Ordinal);
        Assert.Contains("Config(typeof(QuicPublicApiLifecyclePhaseBenchmarksConfig))", benchmark, StringComparison.Ordinal);
        Assert.Contains("GetSupportedImplementations", benchmark, StringComparison.Ordinal);
        Assert.Contains("GetSupportedPhases", benchmark, StringComparison.Ordinal);
        Assert.Contains("Skipping System.Net.Quic lifecycle rows beyond connect/accept/handshake", benchmark, StringComparison.Ordinal);
        Assert.Contains("IterationSetup", benchmark, StringComparison.Ordinal);
        Assert.Contains("IterationCleanup", benchmark, StringComparison.Ordinal);
        Assert.Contains("MemoryDiagnoser", benchmark, StringComparison.Ordinal);
        Assert.Contains("WithInvocationCount(1)", benchmark, StringComparison.Ordinal);
        Assert.Contains("WithUnrollFactor(1)", benchmark, StringComparison.Ordinal);
        Assert.Contains("BenchmarkSwitcher.FromAssembly", program, StringComparison.Ordinal);
        Assert.Contains("QuicPublicApiLifecyclePhaseBenchmarks", readme, StringComparison.Ordinal);
        Assert.Contains("*QuicPublicApiLifecyclePhaseBenchmarks*", readme, StringComparison.Ordinal);

        foreach (string phase in new[]
        {
            "ListenerSetup",
            "ConnectAcceptHandshake",
            "StreamOpenAccept",
            "RequestWriteRead",
            "RequestFin",
            "ConnectionClose",
            "DisposeResources",
        })
        {
            Assert.Contains(phase, benchmark, StringComparison.Ordinal);
        }

        foreach (string apiMember in new[]
        {
            "BenchmarkCase",
            "IncursaQuic",
            "SystemNetQuic",
            "ListenAsync",
            "AcceptConnectionAsync",
            "OpenOutboundStreamAsync",
            "Task.Yield()",
            "WriteAsync",
            "CompleteWritesAsync",
            "CloseAsync",
            "DisposeAsync",
        })
        {
            Assert.Contains(apiMember, benchmark, StringComparison.Ordinal);
        }
    }

    private static string ReadRepositoryFile(string relativePath)
    {
        string repoRoot = FindRepoRoot();
        string candidate = Path.Combine(repoRoot, relativePath);
        if (File.Exists(candidate))
        {
            return File.ReadAllText(candidate);
        }

        throw new InvalidOperationException($"Unable to locate '{relativePath}' under '{repoRoot}'.");
    }

    private static string FindRepoRoot()
    {
        DirectoryInfo? current = new(AppContext.BaseDirectory);
        while (current is not null)
        {
            string gitMarker = Path.Combine(current.FullName, ".git");
            string benchmarkMarker = Path.Combine(current.FullName, "benchmarks", "Incursa.Quic.Benchmarks.csproj");
            string testsMarker = Path.Combine(current.FullName, "tests", "Incursa.Quic.Tests", "Incursa.Quic.Tests.csproj");
            if ((Directory.Exists(gitMarker) || File.Exists(gitMarker))
                && File.Exists(benchmarkMarker)
                && File.Exists(testsMarker))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Unable to locate the repository root for the public lifecycle-phase benchmark tests.");
    }
}
