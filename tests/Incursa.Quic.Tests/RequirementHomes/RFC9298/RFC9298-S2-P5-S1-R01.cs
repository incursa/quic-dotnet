// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9298-S2-P5-S1-R01")]
[Requirement("REQ-QUIC-RFC9298-0003")]
[Requirement("REQ-QUIC-RFC9298-0004")]
[Requirement("REQ-QUIC-RFC9298-0005")]
[Requirement("REQ-QUIC-RFC9298-0006")]
[Requirement("REQ-QUIC-RFC9298-0007")]
[Requirement("REQ-QUIC-RFC9298-0008")]
[Requirement("REQ-QUIC-RFC9298-0009")]
[Requirement("REQ-QUIC-RFC9298-0010")]
[Requirement("REQ-QUIC-RFC9298-0011")]
[Requirement("REQ-QUIC-RFC9298-0012")]
[Requirement("REQ-QUIC-RFC9298-0013")]
[Requirement("REQ-QUIC-RFC9298-0014")]
[Requirement("REQ-QUIC-RFC9298-0015")]
[Requirement("REQ-QUIC-RFC9298-0016")]
[Requirement("REQ-QUIC-RFC9298-0017")]
[Requirement("REQ-QUIC-RFC9298-0018")]
[Requirement("REQ-QUIC-RFC9298-0019")]
[Requirement("REQ-QUIC-RFC9298-0020")]
[Requirement("REQ-QUIC-RFC9298-0024")]
[Requirement("REQ-QUIC-RFC9298-0025")]
[Requirement("REQ-QUIC-RFC9298-0026")]
[Requirement("REQ-QUIC-RFC9298-0027")]
[Requirement("REQ-QUIC-RFC9298-0028")]
[Requirement("REQ-QUIC-RFC9298-0029")]
[Requirement("REQ-QUIC-RFC9298-0030")]
[Requirement("REQ-QUIC-RFC9298-0031")]
[Requirement("REQ-QUIC-RFC9298-0032")]
public sealed class RFC9298_S2_P5_S1_R01
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Rfc9298UriTemplateTraceArtifactsAreLinked()
    {
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-RFC9298.json");
        string architecture = ReadRepositoryFile("specs/architecture/quic/ARC-QUIC-RFC9298-0001.json");
        string workItem = ReadRepositoryFile("specs/work-items/quic/WI-QUIC-RFC9298-0001.json");
        string verification = ReadRepositoryFile("specs/verification/quic/VER-QUIC-RFC9298-0001.json");

        Assert.Contains("ARC-QUIC-RFC9298-0001", spec, StringComparison.Ordinal);
        Assert.Contains("WI-QUIC-RFC9298-0001", spec, StringComparison.Ordinal);
        Assert.Contains("VER-QUIC-RFC9298-0001", spec, StringComparison.Ordinal);
        Assert.Contains("RFC9298-S2-P5-S1-R01", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9298-0032", architecture, StringComparison.Ordinal);
        Assert.Contains("RFC9298-S2-P5-S1-R01", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9298-0032", workItem, StringComparison.Ordinal);
        Assert.Contains("RFC9298-S2-P5-S1-R01", verification, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9298-0032", verification, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Rfc9298UriTemplateCodeAndTestsAreTraceLinked()
    {
        string template = ReadRepositoryFile("src/Incursa.Quic.Http3/Http3ConnectUdpUriTemplate.cs");
        string target = ReadRepositoryFile("src/Incursa.Quic.Http3/Http3ConnectUdpTarget.cs");
        string tests = ReadRepositoryFile("tests/Incursa.Quic.Tests/Http3ConnectUdpUriTemplateTests.cs");

        Assert.Contains("CreateDefault", template, StringComparison.Ordinal);
        Assert.Contains("Expand", template, StringComparison.Ordinal);
        Assert.Contains("ForbiddenOperators", template, StringComparison.Ordinal);
        Assert.Contains("EncodeTargetHost", target, StringComparison.Ordinal);
        Assert.Contains("UriTemplate_RejectsForbiddenLevelFourExpansionOperators", tests, StringComparison.Ordinal);
        Assert.Contains("Target_PercentEncodesIpv6LiteralColons", tests, StringComparison.Ordinal);
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
            string codeMarker = Path.Combine(current.FullName, "src", "Incursa.Quic.Http3", "Http3ConnectUdpUriTemplate.cs");
            if ((Directory.Exists(gitMarker) || File.Exists(gitMarker)) && File.Exists(specMarker) && File.Exists(codeMarker))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Unable to locate the repository root for the RFC 9298 URI template tests.");
    }
}
