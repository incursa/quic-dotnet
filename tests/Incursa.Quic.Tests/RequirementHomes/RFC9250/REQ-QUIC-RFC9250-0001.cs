// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9250-0004")]
[Requirement("REQ-QUIC-RFC9250-0005")]
[Requirement("RFC9250-S4-1-1-P2-R01")]
[Requirement("RFC9250-S4-1-1-P3-R01")]
[Requirement("REQ-QUIC-RFC9250-0010")]
[Requirement("REQ-QUIC-RFC9250-0026")]
[Requirement("REQ-QUIC-RFC9250-0027")]
[Requirement("REQ-QUIC-RFC9250-0028")]
[Requirement("REQ-QUIC-RFC9250-0029")]
[Requirement("REQ-QUIC-RFC9250-0030")]
[Requirement("REQ-QUIC-RFC9250-0031")]
[Requirement("REQ-QUIC-RFC9250-0032")]
[Requirement("REQ-QUIC-RFC9250-0033")]
[Requirement("REQ-QUIC-RFC9250-0134")]
[Requirement("REQ-QUIC-RFC9250-0135")]
[Requirement("REQ-QUIC-RFC9250-0136")]
[Requirement("REQ-QUIC-RFC9250-0137")]
[Requirement("REQ-QUIC-RFC9250-0138")]
[Requirement("REQ-QUIC-RFC9250-0139")]
[Requirement("REQ-QUIC-RFC9250-0140")]
public sealed class REQ_QUIC_RFC9250_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DoqFoundationTraceArtifactsAreLinked()
    {
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-RFC9250.json");
        string architecture = ReadRepositoryFile("specs/architecture/quic/ARC-QUIC-RFC9250-0001.json");
        string workItem = ReadRepositoryFile("specs/work-items/quic/WI-QUIC-RFC9250-0001.json");
        string verification = ReadRepositoryFile("specs/verification/quic/VER-QUIC-RFC9250-0001.json");

        Assert.Contains("ARC-QUIC-RFC9250-0001", spec, StringComparison.Ordinal);
        Assert.Contains("WI-QUIC-RFC9250-0001", spec, StringComparison.Ordinal);
        Assert.Contains("VER-QUIC-RFC9250-0001", spec, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0004", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0010", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0140", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0004", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0010", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0140", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0004", verification, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0010", verification, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0140", verification, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DoqFoundationCodeAndTestsAreTraceLinked()
    {
        string defaults = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqDefaults.cs");
        string errorCodes = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqErrorCode.cs");
        string codec = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqMessageCodec.cs");
        string tests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqFoundationTests.cs");
        string readme = ReadRepositoryFile("src/Incursa.Quic.Dns/README.md");

        Assert.Contains("AlpnToken = \"doq\"", defaults, StringComparison.Ordinal);
        Assert.Contains("DefaultPort = 853", defaults, StringComparison.Ordinal);
        Assert.Contains("ProhibitedPlainDnsPort = 53", defaults, StringComparison.Ordinal);
        Assert.Contains("ErrorReserved = 0xd098ea5e", errorCodes, StringComparison.Ordinal);
        Assert.Contains("LengthPrefixSize = 2", codec, StringComparison.Ordinal);
        Assert.Contains("MessageCodecEncodesTwoOctetLengthPrefix", tests, StringComparison.Ordinal);
        Assert.Contains("ErrorCodeValuesMatchRfc9250Registry", tests, StringComparison.Ordinal);
        Assert.Contains("DNS over QUIC", readme, StringComparison.Ordinal);
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
            string codeMarker = Path.Combine(current.FullName, "src", "Incursa.Quic.Dns", "DoqDefaults.cs");
            if ((Directory.Exists(gitMarker) || File.Exists(gitMarker)) && File.Exists(specMarker) && File.Exists(codeMarker))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Unable to locate the repository root for the RFC 9250 DoQ tests.");
    }
}
