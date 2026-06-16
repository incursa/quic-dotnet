// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9463-0001")]
[Requirement("REQ-QUIC-RFC9463-0008")]
[Requirement("REQ-QUIC-RFC9463-0009")]
[Requirement("REQ-QUIC-RFC9463-0010")]
[Requirement("REQ-QUIC-RFC9463-0022")]
[Requirement("REQ-QUIC-RFC9463-0025")]
[Requirement("REQ-QUIC-RFC9463-0083")]
[Requirement("REQ-QUIC-RFC9463-0086")]
[Requirement("REQ-QUIC-RFC9463-0087")]
[Requirement("REQ-QUIC-RFC9463-0102")]
[Requirement("REQ-QUIC-RFC9463-0109")]
[Requirement("REQ-QUIC-RFC9463-0110")]
[Requirement("REQ-QUIC-RFC9463-0112")]
[Requirement("REQ-QUIC-RFC9463-0114")]
[Requirement("REQ-QUIC-RFC9463-0116")]
public sealed class REQ_QUIC_RFC9463_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Rfc9463EncryptedDnsDiscoveryTraceArtifactsAreLinked()
    {
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-RFC9463.json");
        string architecture = ReadRepositoryFile("specs/architecture/quic/ARC-QUIC-RFC9463-0001.json");
        string workItem = ReadRepositoryFile("specs/work-items/quic/WI-QUIC-RFC9463-0001.json");
        string verification = ReadRepositoryFile("specs/verification/quic/VER-QUIC-RFC9463-0001.json");

        Assert.Contains("ARC-QUIC-RFC9463-0001", spec, StringComparison.Ordinal);
        Assert.Contains("WI-QUIC-RFC9463-0001", spec, StringComparison.Ordinal);
        Assert.Contains("VER-QUIC-RFC9463-0001", spec, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9463-0001", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9463-0116", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9463-0001", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9463-0116", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9463-0001", verification, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9463-0116", verification, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Rfc9463EncryptedDnsDiscoveryCodeAndTestsAreTraceLinked()
    {
        string option = ReadRepositoryFile("src/Incursa.Quic.Dns/EncryptedDnsDiscoveryOption.cs");
        string codes = ReadRepositoryFile("src/Incursa.Quic.Dns/EncryptedDnsDiscoveryOptionCodes.cs");
        string tests = ReadRepositoryFile("tests/Incursa.Quic.Tests/EncryptedDnsDiscoveryOptionTests.cs");

        Assert.Contains("TryCreate", option, StringComparison.Ordinal);
        Assert.Contains("IsForbiddenAddressHintServiceParameter", option, StringComparison.Ordinal);
        Assert.Contains("IsUsableResolverAddress", option, StringComparison.Ordinal);
        Assert.Contains("Dhcpv6OptionV6Dnr = 144", codes, StringComparison.Ordinal);
        Assert.Contains("Dhcpv4OptionV4Dnr = 162", codes, StringComparison.Ordinal);
        Assert.Contains("NeighborDiscoveryEncryptedDnsOptionType = 144", codes, StringComparison.Ordinal);
        Assert.Contains("TryCreateSilentlyFiltersLoopbackAndMulticastAddresses", tests, StringComparison.Ordinal);
        Assert.Contains("TryCreateRejectsForbiddenAddressHintServiceParameters", tests, StringComparison.Ordinal);
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
            string specMarker = Path.Combine(current.FullName, "specs", "requirements", "quic", "SPEC-QUIC-RFC9463.json");
            string codeMarker = Path.Combine(current.FullName, "src", "Incursa.Quic.Dns", "EncryptedDnsDiscoveryOption.cs");
            if ((Directory.Exists(gitMarker) || File.Exists(gitMarker)) && File.Exists(specMarker) && File.Exists(codeMarker))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Unable to locate the repository root for the RFC 9463 tests.");
    }
}
