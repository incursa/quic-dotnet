// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9298-0096")]
[Requirement("REQ-QUIC-RFC9298-0097")]
[Requirement("REQ-QUIC-RFC9298-0098")]
public sealed class REQ_QUIC_RFC9298_0096
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Rfc9298EarlyDatagramPolicyTraceArtifactsAreLinked()
    {
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-RFC9298.json");
        string architecture = ReadRepositoryFile("specs/architecture/quic/ARC-QUIC-RFC9298-0006.json");
        string workItem = ReadRepositoryFile("specs/work-items/quic/WI-QUIC-RFC9298-0006.json");
        string verification = ReadRepositoryFile("specs/verification/quic/VER-QUIC-RFC9298-0006.json");

        Assert.Contains("ARC-QUIC-RFC9298-0006", spec, StringComparison.Ordinal);
        Assert.Contains("WI-QUIC-RFC9298-0006", spec, StringComparison.Ordinal);
        Assert.Contains("VER-QUIC-RFC9298-0006", spec, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9298-0096", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9298-0098", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9298-0096", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9298-0098", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9298-0096", verification, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9298-0098", verification, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Rfc9298EarlyDatagramPolicyCodeAndTestsAreTraceLinked()
    {
        string policy = ReadRepositoryFile("src/Incursa.Quic.Http3/Http3ConnectUdpEarlyDatagramPolicy.cs");
        string tests = ReadRepositoryFile("tests/Incursa.Quic.Tests/Http3ConnectUdpEarlyDatagramPolicyTests.cs");

        Assert.Contains("ClassifyEarlyDatagram", policy, StringComparison.Ordinal);
        Assert.Contains("ShouldApplyBufferingLimits", policy, StringComparison.Ordinal);
        Assert.Contains("ClientMaySendOptimisticDatagramsBeforeResponse", policy, StringComparison.Ordinal);
        Assert.Contains("EarlyDatagramPolicy_DropsOrBuffersBeforeRequest", tests, StringComparison.Ordinal);
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
            string specMarker = Path.Combine(current.FullName, "specs", "requirements", "quic", "SPEC-QUIC-RFC9298.json");
            string codeMarker = Path.Combine(current.FullName, "src", "Incursa.Quic.Http3", "Http3ConnectUdpEarlyDatagramPolicy.cs");
            if ((Directory.Exists(gitMarker) || File.Exists(gitMarker)) && File.Exists(specMarker) && File.Exists(codeMarker))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Unable to locate the repository root for the RFC 9298 early-datagram tests.");
    }
}
