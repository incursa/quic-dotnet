// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9250-S5-5-3-P4-S3-R01")]
public sealed class REQ_QUIC_RFC9250_0106
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DoqAddressValidationTokenPolicyTraceArtifactsAreLinked()
    {
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-RFC9250.json");
        string architecture = ReadRepositoryFile("specs/architecture/quic/ARC-QUIC-RFC9250-0014.json");
        string workItem = ReadRepositoryFile("specs/work-items/quic/WI-QUIC-RFC9250-0014.json");
        string verification = ReadRepositoryFile("specs/verification/quic/VER-QUIC-RFC9250-0014.json");

        Assert.Contains("RFC9250-S5-5-3-P4-S3-R01", spec, StringComparison.Ordinal);
        Assert.Contains("ARC-QUIC-RFC9250-0014", spec, StringComparison.Ordinal);
        Assert.Contains("WI-QUIC-RFC9250-0014", spec, StringComparison.Ordinal);
        Assert.Contains("VER-QUIC-RFC9250-0014", spec, StringComparison.Ordinal);
        Assert.Contains("RFC9250-S5-5-3-P4-S3-R01", architecture, StringComparison.Ordinal);
        Assert.Contains("RFC9250-S5-5-3-P4-S3-R01", workItem, StringComparison.Ordinal);
        Assert.Contains("RFC9250-S5-5-3-P4-S3-R01", verification, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DoqAddressValidationTokenPolicyCodeAndTestsAreTraceLinked()
    {
        string client = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqClient.cs");
        string tests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqStreamLifecycleTests.cs");
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-RFC9250.json");

        Assert.Contains("CanUseAddressValidationToken", client, StringComparison.Ordinal);
        Assert.Contains("UseAddressValidationWithResumptionOnly", client, StringComparison.Ordinal);
        Assert.Contains("AddressValidationTokenPolicyAllowsTokenWithSessionResumption", tests, StringComparison.Ordinal);
        Assert.Contains("AddressValidationTokenPolicyRejectsTokenWithoutSessionResumptionByDefault", tests, StringComparison.Ordinal);
        Assert.Contains("tests/Incursa.Quic.Tests/DoqStreamLifecycleTests.cs::AddressValidationTokenPolicyAllowsTokenWithSessionResumption", spec, StringComparison.Ordinal);
        Assert.Contains("tests/Incursa.Quic.Tests/DoqStreamLifecycleTests.cs::AddressValidationTokenPolicyRejectsTokenWithoutSessionResumptionByDefault", spec, StringComparison.Ordinal);
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

        throw new InvalidOperationException("Unable to locate the repository root for the RFC 9250 DoQ address validation token policy tests.");
    }
}
