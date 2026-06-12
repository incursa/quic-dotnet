// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9250-0098")]
public sealed class REQ_QUIC_RFC9250_0098
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DoqPaddingBenchmarkTraceArtifactsAreLinked()
    {
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-RFC9250.json");
        string architecture = ReadRepositoryFile("specs/architecture/quic/ARC-QUIC-RFC9250-0018.json");
        string workItem = ReadRepositoryFile("specs/work-items/quic/WI-QUIC-RFC9250-0018.json");
        string verification = ReadRepositoryFile("specs/verification/quic/VER-QUIC-RFC9250-0018.json");

        Assert.Contains("REQ-QUIC-RFC9250-0098", spec, StringComparison.Ordinal);
        Assert.Contains("ARC-QUIC-RFC9250-0018", spec, StringComparison.Ordinal);
        Assert.Contains("WI-QUIC-RFC9250-0018", spec, StringComparison.Ordinal);
        Assert.Contains("VER-QUIC-RFC9250-0018", spec, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0098", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0098", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0098", verification, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [CoverageType(RequirementCoverageType.Benchmark)]
    [Trait("Category", "Positive")]
    public void DoqPaddingBenchmarkSuiteIsTraceLinked()
    {
        string benchmark = ReadRepositoryFile("benchmarks/DoqPaddingBenchmarks.cs");
        string project = ReadRepositoryFile("benchmarks/Incursa.Quic.Benchmarks.csproj");
        string readme = ReadRepositoryFile("benchmarks/README.md");
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-RFC9250.json");
        string verification = ReadRepositoryFile("specs/verification/quic/VER-QUIC-RFC9250-0018.json");

        Assert.Contains("DoqPaddingBenchmarks", benchmark, StringComparison.Ordinal);
        Assert.Contains("MemoryDiagnoser", benchmark, StringComparison.Ordinal);
        Assert.Contains("PadQueryWithoutExistingOpt", benchmark, StringComparison.Ordinal);
        Assert.Contains("PadQueryWithExistingOpt", benchmark, StringComparison.Ordinal);
        Assert.Contains("PadNearMaximumMessage", benchmark, StringComparison.Ordinal);
        Assert.Contains("Incursa.Quic.Dns.csproj", project, StringComparison.Ordinal);
        Assert.Contains("DoqPaddingBenchmarks", readme, StringComparison.Ordinal);
        Assert.Contains("tests/Incursa.Quic.Tests/RequirementHomes/RFC9250/REQ-QUIC-RFC9250-0098.cs::DoqPaddingBenchmarkSuiteIsTraceLinked", spec, StringComparison.Ordinal);
        Assert.Contains("benchmarks/DoqPaddingBenchmarks.cs", verification, StringComparison.Ordinal);
        Assert.Contains("DoqPaddingBenchmarks-report-github.md", verification, StringComparison.Ordinal);
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
            string specMarker = Path.Combine(current.FullName, "specs", "requirements", "quic", "SPEC-QUIC-RFC9250.json");
            string benchmarkMarker = Path.Combine(current.FullName, "benchmarks", "Incursa.Quic.Benchmarks.csproj");
            if ((Directory.Exists(gitMarker) || File.Exists(gitMarker)) && File.Exists(specMarker) && File.Exists(benchmarkMarker))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Unable to locate the repository root for the RFC 9250 DoQ padding benchmark tests.");
    }
}
