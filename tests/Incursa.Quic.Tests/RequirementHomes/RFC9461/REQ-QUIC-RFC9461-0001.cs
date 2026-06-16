// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9461-0001")]
[Requirement("REQ-QUIC-RFC9461-0002")]
[Requirement("REQ-QUIC-RFC9461-0003")]
[Requirement("REQ-QUIC-RFC9461-0004")]
[Requirement("REQ-QUIC-RFC9461-0009")]
[Requirement("REQ-QUIC-RFC9461-0029")]
[Requirement("REQ-QUIC-RFC9461-0033")]
[Requirement("REQ-QUIC-RFC9461-0036")]
[Requirement("REQ-QUIC-RFC9461-0038")]
public sealed class REQ_QUIC_RFC9461_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Rfc9461ServiceBindingTraceArtifactsAreLinked()
    {
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-RFC9461.json");
        string architecture = ReadRepositoryFile("specs/architecture/quic/ARC-QUIC-RFC9461-0001.json");
        string workItem = ReadRepositoryFile("specs/work-items/quic/WI-QUIC-RFC9461-0001.json");
        string verification = ReadRepositoryFile("specs/verification/quic/VER-QUIC-RFC9461-0001.json");

        Assert.Contains("ARC-QUIC-RFC9461-0001", spec, StringComparison.Ordinal);
        Assert.Contains("WI-QUIC-RFC9461-0001", spec, StringComparison.Ordinal);
        Assert.Contains("VER-QUIC-RFC9461-0001", spec, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9461-0001", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9461-0002", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9461-0038", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9461-0001", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9461-0002", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9461-0038", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9461-0001", verification, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9461-0002", verification, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9461-0038", verification, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Rfc9461ServiceBindingCodeAndTestsAreTraceLinked()
    {
        string defaults = ReadRepositoryFile("src/Incursa.Quic.Dns/DnsServiceBindingDefaults.cs");
        string transports = ReadRepositoryFile("src/Incursa.Quic.Dns/DnsServiceTransport.cs");
        string tests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DnsServiceBindingDefaultsTests.cs");

        Assert.Contains("Scheme = \"dns\"", defaults, StringComparison.Ordinal);
        Assert.Contains("NodeName = \"_dns\"", defaults, StringComparison.Ordinal);
        Assert.Contains("CleartextDnsDefaultPort = 53", defaults, StringComparison.Ordinal);
        Assert.Contains("DnsOverQuicDefaultPort = DoqDefaults.DefaultPort", defaults, StringComparison.Ordinal);
        Assert.Contains("DnsOverHttpsDefaultPort = 443", defaults, StringComparison.Ordinal);
        Assert.Contains("DnsOverQuic", transports, StringComparison.Ordinal);
        Assert.Contains("CreateServiceNameCombinesPortPrefixAndAuthenticationHostname", tests, StringComparison.Ordinal);
        Assert.Contains("AuthenticationNameAcceptsDnsHostnamesAndLiteralIpAddresses", tests, StringComparison.Ordinal);
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
            string specMarker = Path.Combine(current.FullName, "specs", "requirements", "quic", "SPEC-QUIC-RFC9461.json");
            string codeMarker = Path.Combine(current.FullName, "src", "Incursa.Quic.Dns", "DnsServiceBindingDefaults.cs");
            if ((Directory.Exists(gitMarker) || File.Exists(gitMarker)) && File.Exists(specMarker) && File.Exists(codeMarker))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Unable to locate the repository root for the RFC 9461 tests.");
    }
}
