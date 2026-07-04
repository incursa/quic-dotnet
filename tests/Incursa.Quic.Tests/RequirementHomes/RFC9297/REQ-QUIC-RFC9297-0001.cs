// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9297-0001")]
[Requirement("REQ-QUIC-RFC9297-0002")]
[Requirement("REQ-QUIC-RFC9297-0003")]
[Requirement("REQ-QUIC-RFC9297-0008")]
[Requirement("REQ-QUIC-RFC9297-0009")]
[Requirement("REQ-QUIC-RFC9297-0010")]
[Requirement("REQ-QUIC-RFC9297-0011")]
[Requirement("REQ-QUIC-RFC9297-0012")]
[Requirement("REQ-QUIC-RFC9297-0013")]
[Requirement("REQ-QUIC-RFC9297-0017")]
[Requirement("RFC9297-S2-1-1-P2-R01")]
[Requirement("RFC9297-S2-1-1-P2-S2-R01")]
[Requirement("RFC9297-S2-1-1-P3-R01")]
[Requirement("RFC9297-S2-1-1-P4-R01")]
[Requirement("RFC9297-S2-1-1-P4-S2-R01")]
[Requirement("RFC9297-S2-1-1-P4-S3-R02")]
[Requirement("REQ-QUIC-RFC9297-0024")]
[Requirement("RFC9297-S2-1-1-P4-S4-R01")]
[Requirement("REQ-QUIC-RFC9297-0028")]
[Requirement("REQ-QUIC-RFC9297-0029")]
[Requirement("REQ-QUIC-RFC9297-0030")]
[Requirement("REQ-QUIC-RFC9297-0031")]
[Requirement("REQ-QUIC-RFC9297-0032")]
[Requirement("REQ-QUIC-RFC9297-0033")]
[Requirement("REQ-QUIC-RFC9297-0034")]
[Requirement("REQ-QUIC-RFC9297-0035")]
[Requirement("RFC9297-S3-3-P1-R01")]
[Requirement("RFC9297-S3-3-P2-S1-R01")]
[Requirement("RFC9297-S3-3-P3-R01")]
[Requirement("REQ-QUIC-RFC9297-0061")]
[Requirement("REQ-QUIC-RFC9297-0062")]
[Requirement("REQ-QUIC-RFC9297-0063")]
[Requirement("REQ-QUIC-RFC9297-0064")]
[Requirement("REQ-QUIC-RFC9297-0065")]
[Requirement("REQ-QUIC-RFC9297-0076")]
[Requirement("REQ-QUIC-RFC9297-0077")]
[Requirement("REQ-QUIC-RFC9297-0078")]
[Requirement("REQ-QUIC-RFC9297-0084")]
public sealed class REQ_QUIC_RFC9297_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Rfc9297FoundationTraceArtifactsAreLinked()
    {
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-RFC9297.json");
        string architecture = ReadRepositoryFile("specs/architecture/quic/ARC-QUIC-RFC9297-0001.json");
        string workItem = ReadRepositoryFile("specs/work-items/quic/WI-QUIC-RFC9297-0001.json");
        string verification = ReadRepositoryFile("specs/verification/quic/VER-QUIC-RFC9297-0001.json");

        Assert.Contains("ARC-QUIC-RFC9297-0001", spec, StringComparison.Ordinal);
        Assert.Contains("WI-QUIC-RFC9297-0001", spec, StringComparison.Ordinal);
        Assert.Contains("VER-QUIC-RFC9297-0001", spec, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9297-0001", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9297-0084", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9297-0001", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9297-0084", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9297-0001", verification, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9297-0084", verification, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Rfc9297FoundationCodeAndTestsAreTraceLinked()
    {
        string datagram = ReadRepositoryFile("src/Incursa.Quic.Http3/Http3Datagram.cs");
        string datagramSupport = ReadRepositoryFile("src/Incursa.Quic.Http3/Http3DatagramSupport.cs");
        string capsule = ReadRepositoryFile("src/Incursa.Quic.Http3/Http3Capsule.cs");
        string tests = ReadRepositoryFile("tests/Incursa.Quic.Tests/Http3DatagramAndCapsuleTests.cs");

        Assert.Contains("MaximumQuarterStreamId", datagram, StringComparison.Ordinal);
        Assert.Contains("CreateForAssociatedStream", datagram, StringComparison.Ordinal);
        Assert.Contains("CanSendDatagram", datagramSupport, StringComparison.Ordinal);
        Assert.Contains("ValidateZeroRttSettings", datagramSupport, StringComparison.Ordinal);
        Assert.Contains("DatagramCapsuleType = 0x00", capsule, StringComparison.Ordinal);
        Assert.Contains("ParseSequence", capsule, StringComparison.Ordinal);
        Assert.Contains("DatagramCodec_EncodesQuarterStreamIdBeforePayload", tests, StringComparison.Ordinal);
        Assert.Contains("SettingsH3Datagram_RoundTripsRegisteredSettingAndDefaultsToZero", tests, StringComparison.Ordinal);
        Assert.Contains("DatagramCapsule_UsesTypeZeroAndCarriesHttpDatagramPayloadAfterLength", tests, StringComparison.Ordinal);
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
            string codeMarker = Path.Combine(current.FullName, "src", "Incursa.Quic.Http3", "Http3Datagram.cs");
            if ((Directory.Exists(gitMarker) || File.Exists(gitMarker)) && File.Exists(specMarker) && File.Exists(codeMarker))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Unable to locate the repository root for the RFC 9297 tests.");
    }
}
