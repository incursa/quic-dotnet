// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9250-S5-2-P3-S1-R01")]
public sealed class REQ_QUIC_RFC9250_0088
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DoqOpportunisticBackoffTraceArtifactsAreLinked()
    {
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-RFC9250.json");
        string architecture = ReadRepositoryFile("specs/architecture/quic/ARC-QUIC-RFC9250-0016.json");
        string workItem = ReadRepositoryFile("specs/work-items/quic/WI-QUIC-RFC9250-0016.json");
        string verification = ReadRepositoryFile("specs/verification/quic/VER-QUIC-RFC9250-0016.json");

        Assert.Contains("RFC9250-S5-2-P3-S1-R01", spec, StringComparison.Ordinal);
        Assert.Contains("ARC-QUIC-RFC9250-0016", spec, StringComparison.Ordinal);
        Assert.Contains("WI-QUIC-RFC9250-0016", spec, StringComparison.Ordinal);
        Assert.Contains("VER-QUIC-RFC9250-0016", spec, StringComparison.Ordinal);
        Assert.Contains("RFC9250-S5-2-P3-S1-R01", architecture, StringComparison.Ordinal);
        Assert.Contains("RFC9250-S5-2-P3-S1-R01", workItem, StringComparison.Ordinal);
        Assert.Contains("RFC9250-S5-2-P3-S1-R01", verification, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DoqOpportunisticBackoffCodeAndTestsAreTraceLinked()
    {
        string client = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqClient.cs");
        string cache = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqFallbackCache.cs");
        string tests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqStreamLifecycleTests.cs");
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-RFC9250.json");

        Assert.Contains("Profile == DoqClientProfile.Opportunistic", client, StringComparison.Ordinal);
        Assert.Contains("EnsureNotBackedOff", client, StringComparison.Ordinal);
        Assert.Contains("RecordFailure(string endpoint)", cache, StringComparison.Ordinal);
        Assert.Contains("OpportunisticProfileRejectsQueryWhileEndpointIsBackedOff", tests, StringComparison.Ordinal);
        Assert.Contains("OpportunisticProfileAllowsQueryAfterBackoffIsCleared", tests, StringComparison.Ordinal);
        Assert.Contains("tests/Incursa.Quic.Tests/DoqStreamLifecycleTests.cs::OpportunisticProfileRejectsQueryWhileEndpointIsBackedOff", spec, StringComparison.Ordinal);
        Assert.Contains("tests/Incursa.Quic.Tests/DoqStreamLifecycleTests.cs::OpportunisticProfileAllowsQueryAfterBackoffIsCleared", spec, StringComparison.Ordinal);
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
            string codeMarker = Path.Combine(current.FullName, "src", "Incursa.Quic.Dns", "DoqClient.cs");
            if ((Directory.Exists(gitMarker) || File.Exists(gitMarker)) && File.Exists(specMarker) && File.Exists(codeMarker))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Unable to locate the repository root for the RFC 9250 DoQ opportunistic backoff tests.");
    }
}
