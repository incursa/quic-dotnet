// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9297-0036")]
[Requirement("REQ-QUIC-RFC9297-0037")]
[Requirement("REQ-QUIC-RFC9297-0038")]
[Requirement("REQ-QUIC-RFC9297-0039")]
[Requirement("REQ-QUIC-RFC9297-0040")]
[Requirement("REQ-QUIC-RFC9297-0041")]
[Requirement("REQ-QUIC-RFC9297-0042")]
[Requirement("REQ-QUIC-RFC9297-0043")]
[Requirement("REQ-QUIC-RFC9297-0044")]
[Requirement("REQ-QUIC-RFC9297-0045")]
[Requirement("REQ-QUIC-RFC9297-0052")]
[Requirement("REQ-QUIC-RFC9297-0053")]
[Requirement("RFC9297-S3-4-P1-S1-R02")]
[Requirement("RFC9297-S3-4-P1-S3-R01")]
[Requirement("REQ-QUIC-RFC9297-0056")]
[Requirement("REQ-QUIC-RFC9297-0057")]
[Requirement("RFC9297-S3-4-P3-R01")]
[Requirement("RFC9297-S3-4-P4-R01")]
[Requirement("RFC9297-S3-4-P5-R01")]
[Requirement("REQ-QUIC-RFC9297-0079")]
[Requirement("RFC9297-S5-4-P1-S3-R01")]
[Requirement("REQ-QUIC-RFC9297-0081")]
[Requirement("REQ-QUIC-RFC9297-0082")]
[Requirement("RFC9297-S5-4-P3-S2-R02")]
public sealed class REQ_QUIC_RFC9297_0036
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Rfc9297CapsuleProtocolPolicyTraceArtifactsAreLinked()
    {
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-RFC9297.json");
        string architecture = ReadRepositoryFile("specs/architecture/quic/ARC-QUIC-RFC9297-0002.json");
        string workItem = ReadRepositoryFile("specs/work-items/quic/WI-QUIC-RFC9297-0002.json");
        string verification = ReadRepositoryFile("specs/verification/quic/VER-QUIC-RFC9297-0002.json");

        Assert.Contains("ARC-QUIC-RFC9297-0002", spec, StringComparison.Ordinal);
        Assert.Contains("WI-QUIC-RFC9297-0002", spec, StringComparison.Ordinal);
        Assert.Contains("VER-QUIC-RFC9297-0002", spec, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9297-0036", architecture, StringComparison.Ordinal);
        Assert.Contains("RFC9297-S5-4-P3-S2-R02", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9297-0036", workItem, StringComparison.Ordinal);
        Assert.Contains("RFC9297-S5-4-P3-S2-R02", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9297-0036", verification, StringComparison.Ordinal);
        Assert.Contains("RFC9297-S5-4-P3-S2-R02", verification, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Rfc9297CapsuleProtocolPolicyCodeAndTestsAreTraceLinked()
    {
        string policy = ReadRepositoryFile("src/Incursa.Quic.Http3/Http3CapsuleProtocol.cs");
        string tests = ReadRepositoryFile("tests/Incursa.Quic.Tests/Http3CapsuleProtocolPolicyTests.cs");

        Assert.Contains("CapsuleProtocolHeaderName", policy, StringComparison.Ordinal);
        Assert.Contains("ValidateHttp3Usage", policy, StringComparison.Ordinal);
        Assert.Contains("TryParseCapsuleProtocolHeaderValue", policy, StringComparison.Ordinal);
        Assert.Contains("ValidateCapsuleTypeRegistration", policy, StringComparison.Ordinal);
        Assert.Contains("CapsuleProtocol_RejectsDisallowedStatusesAsMalformed", tests, StringComparison.Ordinal);
        Assert.Contains("CapsuleProtocolHeader_ParsesTrueBooleanAndIgnoresUnknownParameters", tests, StringComparison.Ordinal);
        Assert.Contains("CapsuleProtocolRegistry_IdentifiesReservedCapsuleTypeValues", tests, StringComparison.Ordinal);
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
            string codeMarker = Path.Combine(current.FullName, "src", "Incursa.Quic.Http3", "Http3CapsuleProtocol.cs");
            if ((Directory.Exists(gitMarker) || File.Exists(gitMarker)) && File.Exists(specMarker) && File.Exists(codeMarker))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Unable to locate the repository root for the RFC 9297 policy tests.");
    }
}
