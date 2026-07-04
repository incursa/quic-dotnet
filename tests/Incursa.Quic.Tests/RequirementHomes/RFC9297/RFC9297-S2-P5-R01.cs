// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9297-S2-P5-R01")]
[Requirement("RFC9297-S2-P6-R01")]
[Requirement("RFC9297-S2-P6-S1-R01")]
[Requirement("RFC9297-S2-P6-S2-R01")]
[Requirement("REQ-QUIC-RFC9297-0014")]
[Requirement("REQ-QUIC-RFC9297-0015")]
[Requirement("REQ-QUIC-RFC9297-0016")]
[Requirement("REQ-QUIC-RFC9297-0026")]
[Requirement("REQ-QUIC-RFC9297-0027")]
[Requirement("REQ-QUIC-RFC9297-0046")]
[Requirement("RFC9297-S3-3-P2-R01")]
[Requirement("RFC9297-S3-3-P2-S2-R01")]
[Requirement("REQ-QUIC-RFC9297-0066")]
[Requirement("REQ-QUIC-RFC9297-0067")]
[Requirement("REQ-QUIC-RFC9297-0068")]
[Requirement("REQ-QUIC-RFC9297-0069")]
[Requirement("REQ-QUIC-RFC9297-0070")]
[Requirement("REQ-QUIC-RFC9297-0071")]
[Requirement("REQ-QUIC-RFC9297-0072")]
[Requirement("REQ-QUIC-RFC9297-0073")]
[Requirement("REQ-QUIC-RFC9297-0074")]
[Requirement("REQ-QUIC-RFC9297-0075")]
public sealed class REQ_QUIC_RFC9297_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Rfc9297DatagramLifecycleTraceArtifactsAreLinked()
    {
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-RFC9297.json");
        string architecture = ReadRepositoryFile("specs/architecture/quic/ARC-QUIC-RFC9297-0003.json");
        string workItem = ReadRepositoryFile("specs/work-items/quic/WI-QUIC-RFC9297-0003.json");
        string verification = ReadRepositoryFile("specs/verification/quic/VER-QUIC-RFC9297-0003.json");

        Assert.Contains("ARC-QUIC-RFC9297-0003", spec, StringComparison.Ordinal);
        Assert.Contains("WI-QUIC-RFC9297-0003", spec, StringComparison.Ordinal);
        Assert.Contains("VER-QUIC-RFC9297-0003", spec, StringComparison.Ordinal);
        Assert.Contains("RFC9297-S2-P5-R01", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9297-0075", architecture, StringComparison.Ordinal);
        Assert.Contains("RFC9297-S2-P5-R01", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9297-0075", workItem, StringComparison.Ordinal);
        Assert.Contains("RFC9297-S2-P5-R01", verification, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9297-0075", verification, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Rfc9297DatagramLifecycleCodeAndTestsAreTraceLinked()
    {
        string lifecycle = ReadRepositoryFile("src/Incursa.Quic.Http3/Http3DatagramLifecycle.cs");
        string intermediary = ReadRepositoryFile("src/Incursa.Quic.Http3/Http3DatagramIntermediaryPolicy.cs");
        string lifecycleTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/Http3DatagramLifecyclePolicyTests.cs");
        string intermediaryTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/Http3DatagramIntermediaryPolicyTests.cs");

        Assert.Contains("SelectSendAction", lifecycle, StringComparison.Ordinal);
        Assert.Contains("SelectReceiveAction", lifecycle, StringComparison.Ordinal);
        Assert.Contains("CanStartCapsuleProtocolOnHttp1", lifecycle, StringComparison.Ordinal);
        Assert.Contains("SelectForwardingAction", intermediary, StringComparison.Ordinal);
        Assert.Contains("ValidateCapsulePayloadLength", intermediary, StringComparison.Ordinal);
        Assert.Contains("DatagramLifecycle_AbortsUnsupportedRequestsWithH3DatagramError", lifecycleTests, StringComparison.Ordinal);
        Assert.Contains("IntermediaryPolicy_ReencodesBetweenDatagramFramesAndCapsulesWhenIdentified", intermediaryTests, StringComparison.Ordinal);
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
            string specMarker = Path.Combine(current.FullName, "specs", "requirements", "quic", "SPEC-QUIC-RFC9297.json");
            string codeMarker = Path.Combine(current.FullName, "src", "Incursa.Quic.Http3", "Http3DatagramLifecycle.cs");
            if ((Directory.Exists(gitMarker) || File.Exists(gitMarker)) && File.Exists(specMarker) && File.Exists(codeMarker))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Unable to locate the repository root for the RFC 9297 lifecycle tests.");
    }
}
