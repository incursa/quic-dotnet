// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9298-0053")]
[Requirement("REQ-QUIC-RFC9298-0054")]
[Requirement("REQ-QUIC-RFC9298-0055")]
[Requirement("REQ-QUIC-RFC9298-0056")]
[Requirement("REQ-QUIC-RFC9298-0057")]
[Requirement("REQ-QUIC-RFC9298-0058")]
[Requirement("REQ-QUIC-RFC9298-0059")]
[Requirement("REQ-QUIC-RFC9298-0060")]
[Requirement("REQ-QUIC-RFC9298-0061")]
[Requirement("REQ-QUIC-RFC9298-0062")]
[Requirement("REQ-QUIC-RFC9298-0063")]
[Requirement("REQ-QUIC-RFC9298-0064")]
public sealed class REQ_QUIC_RFC9298_0053
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Rfc9298Http11UpgradePolicyTraceArtifactsAreLinked()
    {
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-RFC9298.json");
        string architecture = ReadRepositoryFile("specs/architecture/quic/ARC-QUIC-RFC9298-0007.json");
        string workItem = ReadRepositoryFile("specs/work-items/quic/WI-QUIC-RFC9298-0007.json");
        string verification = ReadRepositoryFile("specs/verification/quic/VER-QUIC-RFC9298-0007.json");

        Assert.Contains("ARC-QUIC-RFC9298-0007", spec, StringComparison.Ordinal);
        Assert.Contains("WI-QUIC-RFC9298-0007", spec, StringComparison.Ordinal);
        Assert.Contains("VER-QUIC-RFC9298-0007", spec, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9298-0053", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9298-0064", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9298-0053", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9298-0064", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9298-0053", verification, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9298-0064", verification, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Rfc9298Http11UpgradePolicyCodeAndTestsAreTraceLinked()
    {
        string policy = ReadRepositoryFile("src/Incursa.Quic.Http3/Http3ConnectUdpHttp11UpgradePolicy.cs");
        string tests = ReadRepositoryFile("tests/Incursa.Quic.Tests/Http3ConnectUdpHttp11UpgradePolicyTests.cs");

        Assert.Contains("BuildUpgradeRequestHeaders", policy, StringComparison.Ordinal);
        Assert.Contains("ValidateUpgradeRequest", policy, StringComparison.Ordinal);
        Assert.Contains("ValidateSwitchingProtocolsResponse", policy, StringComparison.Ordinal);
        Assert.Contains("UpgradeRequest_UsesGetMethod", tests, StringComparison.Ordinal);
        Assert.Contains("UpgradeResponse_UsesSwitchingProtocolsStatus", tests, StringComparison.Ordinal);
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
            string codeMarker = Path.Combine(current.FullName, "src", "Incursa.Quic.Http3", "Http3ConnectUdpHttp11UpgradePolicy.cs");
            if ((Directory.Exists(gitMarker) || File.Exists(gitMarker)) && File.Exists(specMarker) && File.Exists(codeMarker))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Unable to locate the repository root for the RFC 9298 HTTP/1.1 upgrade tests.");
    }
}
