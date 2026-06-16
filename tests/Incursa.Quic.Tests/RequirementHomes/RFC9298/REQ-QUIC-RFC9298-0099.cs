// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9298-0099")]
[Requirement("REQ-QUIC-RFC9298-0100")]
[Requirement("REQ-QUIC-RFC9298-0101")]
[Requirement("REQ-QUIC-RFC9298-0102")]
[Requirement("REQ-QUIC-RFC9298-0103")]
[Requirement("REQ-QUIC-RFC9298-0104")]
[Requirement("REQ-QUIC-RFC9298-0105")]
[Requirement("REQ-QUIC-RFC9298-0106")]
[Requirement("REQ-QUIC-RFC9298-0107")]
[Requirement("REQ-QUIC-RFC9298-0108")]
[Requirement("REQ-QUIC-RFC9298-0109")]
[Requirement("REQ-QUIC-RFC9298-0110")]
[Requirement("REQ-QUIC-RFC9298-0111")]
[Requirement("REQ-QUIC-RFC9298-0112")]
[Requirement("REQ-QUIC-RFC9298-0113")]
[Requirement("REQ-QUIC-RFC9298-0114")]
[Requirement("REQ-QUIC-RFC9298-0115")]
public sealed class REQ_QUIC_RFC9298_0099
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Rfc9298ForwardingPolicyTraceArtifactsAreLinked()
    {
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-RFC9298.json");
        string architecture = ReadRepositoryFile("specs/architecture/quic/ARC-QUIC-RFC9298-0005.json");
        string workItem = ReadRepositoryFile("specs/work-items/quic/WI-QUIC-RFC9298-0005.json");
        string verification = ReadRepositoryFile("specs/verification/quic/VER-QUIC-RFC9298-0005.json");

        Assert.Contains("ARC-QUIC-RFC9298-0005", spec, StringComparison.Ordinal);
        Assert.Contains("WI-QUIC-RFC9298-0005", spec, StringComparison.Ordinal);
        Assert.Contains("VER-QUIC-RFC9298-0005", spec, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9298-0099", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9298-0115", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9298-0099", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9298-0115", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9298-0099", verification, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9298-0115", verification, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Rfc9298ForwardingPolicyCodeAndTestsAreTraceLinked()
    {
        string policy = ReadRepositoryFile("src/Incursa.Quic.Http3/Http3ConnectUdpForwardingPolicy.cs");
        string tests = ReadRepositoryFile("tests/Incursa.Quic.Tests/Http3ConnectUdpForwardingPolicyTests.cs");

        Assert.Contains("AvoidIncreasingBurstiness", policy, StringComparison.Ordinal);
        Assert.Contains("CanDisableCongestionControl", policy, StringComparison.Ordinal);
        Assert.Contains("ShouldDropOversizedUdpPayload", policy, StringComparison.Ordinal);
        Assert.Contains("OutboundUdpEcnCodepoint", policy, StringComparison.Ordinal);
        Assert.Contains("ForwardingPolicy_AvoidsIncreasingUdpBurstiness", tests, StringComparison.Ordinal);
        Assert.Contains("ForwardingPolicy_SetsOutboundUdpEcnToNotEct", tests, StringComparison.Ordinal);
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
            string codeMarker = Path.Combine(current.FullName, "src", "Incursa.Quic.Http3", "Http3ConnectUdpForwardingPolicy.cs");
            if ((Directory.Exists(gitMarker) || File.Exists(gitMarker)) && File.Exists(specMarker) && File.Exists(codeMarker))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Unable to locate the repository root for the RFC 9298 forwarding-policy tests.");
    }
}
