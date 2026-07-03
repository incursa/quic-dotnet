// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9298-0073")]
[Requirement("REQ-QUIC-RFC9298-0074")]
[Requirement("REQ-QUIC-RFC9298-0075")]
[Requirement("REQ-QUIC-RFC9298-0076")]
[Requirement("REQ-QUIC-RFC9298-0077")]
[Requirement("REQ-QUIC-RFC9298-0078")]
[Requirement("REQ-QUIC-RFC9298-0079")]
[Requirement("REQ-QUIC-RFC9298-0080")]
[Requirement("REQ-QUIC-RFC9298-0081")]
[Requirement("RFC9298-S4-P2-S5-R01")]
[Requirement("REQ-QUIC-RFC9298-0083")]
[Requirement("RFC9298-S4-P3-S2-R01")]
[Requirement("REQ-QUIC-RFC9298-0085")]
[Requirement("REQ-QUIC-RFC9298-0086")]
[Requirement("REQ-QUIC-RFC9298-0087")]
[Requirement("REQ-QUIC-RFC9298-0088")]
[Requirement("REQ-QUIC-RFC9298-0089")]
[Requirement("REQ-QUIC-RFC9298-0090")]
[Requirement("REQ-QUIC-RFC9298-0091")]
[Requirement("REQ-QUIC-RFC9298-0092")]
[Requirement("REQ-QUIC-RFC9298-0093")]
[Requirement("REQ-QUIC-RFC9298-0094")]
[Requirement("REQ-QUIC-RFC9298-0095")]
public sealed class REQ_QUIC_RFC9298_0073
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Rfc9298DatagramContextTraceArtifactsAreLinked()
    {
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-RFC9298.json");
        string architecture = ReadRepositoryFile("specs/architecture/quic/ARC-QUIC-RFC9298-0003.json");
        string workItem = ReadRepositoryFile("specs/work-items/quic/WI-QUIC-RFC9298-0003.json");
        string verification = ReadRepositoryFile("specs/verification/quic/VER-QUIC-RFC9298-0003.json");

        Assert.Contains("ARC-QUIC-RFC9298-0003", spec, StringComparison.Ordinal);
        Assert.Contains("WI-QUIC-RFC9298-0003", spec, StringComparison.Ordinal);
        Assert.Contains("VER-QUIC-RFC9298-0003", spec, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9298-0073", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9298-0095", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9298-0073", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9298-0095", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9298-0073", verification, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9298-0095", verification, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Rfc9298DatagramContextCodeAndTestsAreTraceLinked()
    {
        string datagram = ReadRepositoryFile("src/Incursa.Quic.Http3/Http3ConnectUdpDatagram.cs");
        string registry = ReadRepositoryFile("src/Incursa.Quic.Http3/Http3ConnectUdpContextIdRegistry.cs");
        string policy = ReadRepositoryFile("src/Incursa.Quic.Http3/Http3ConnectUdpDatagramPolicy.cs");
        string tests = ReadRepositoryFile("tests/Incursa.Quic.Tests/Http3ConnectUdpDatagramTests.cs");

        Assert.Contains("MaximumContextId", datagram, StringComparison.Ordinal);
        Assert.Contains("MaximumUdpPayloadLength", datagram, StringComparison.Ordinal);
        Assert.Contains("AllocateClientContextId", registry, StringComparison.Ordinal);
        Assert.Contains("ClassifyUnknownContextId", policy, StringComparison.Ordinal);
        Assert.Contains("DatagramPayload_ContextIdFollowsQuarterStreamIdInHttp3Datagram", tests, StringComparison.Ordinal);
        Assert.Contains("UdpPayload_RejectsOversizedContextIdZeroPayloadsWithDatagramError", tests, StringComparison.Ordinal);
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
            string codeMarker = Path.Combine(current.FullName, "src", "Incursa.Quic.Http3", "Http3ConnectUdpDatagram.cs");
            if ((Directory.Exists(gitMarker) || File.Exists(gitMarker)) && File.Exists(specMarker) && File.Exists(codeMarker))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Unable to locate the repository root for the RFC 9298 datagram Context ID tests.");
    }
}
