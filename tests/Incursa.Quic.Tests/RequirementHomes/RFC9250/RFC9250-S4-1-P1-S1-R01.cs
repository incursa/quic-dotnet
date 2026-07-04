// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9250-0052")]
[Requirement("REQ-QUIC-RFC9250-0053")]
[Requirement("REQ-QUIC-RFC9250-0055")]
public sealed class REQ_QUIC_RFC9250_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DoqProtocolErrorTraceArtifactsAreLinked()
    {
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-RFC9250.json");
        string architecture = ReadRepositoryFile("specs/architecture/quic/ARC-QUIC-RFC9250-0004.json");
        string workItem = ReadRepositoryFile("specs/work-items/quic/WI-QUIC-RFC9250-0004.json");
        string verification = ReadRepositoryFile("specs/verification/quic/VER-QUIC-RFC9250-0004.json");

        Assert.Contains("ARC-QUIC-RFC9250-0004", spec, StringComparison.Ordinal);
        Assert.Contains("WI-QUIC-RFC9250-0004", spec, StringComparison.Ordinal);
        Assert.Contains("VER-QUIC-RFC9250-0004", spec, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0052", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0053", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0055", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0052", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0053", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0055", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0052", verification, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0053", verification, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0055", verification, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DoqProtocolErrorCodeAndTestsAreTraceLinked()
    {
        string client = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqClient.cs");
        string server = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqServer.cs");
        string stream = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqStream.cs");
        string tests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqStreamLifecycleTests.cs");

        Assert.Contains("ValidateZeroMessageId", client, StringComparison.Ordinal);
        Assert.Contains("ValidateZeroMessageId", server, StringComparison.Ordinal);
        Assert.Contains("ReadSingleMessageUntilFinAsync", stream, StringComparison.Ordinal);
        Assert.Contains("The DoQ stream contained more than one DNS message.", stream, StringComparison.Ordinal);
        Assert.Contains("ServerRejectsIncompleteDoqQueryFrame", tests, StringComparison.Ordinal);
        Assert.Contains("ServerTreatsNonZeroQueryMessageIdAsFatalProtocolError", tests, StringComparison.Ordinal);
        Assert.Contains("ClientTreatsNonZeroResponseMessageIdAsFatalProtocolError", tests, StringComparison.Ordinal);
        Assert.Contains("ServerTreatsMultipleQueriesOnOneStreamAsFatalProtocolError", tests, StringComparison.Ordinal);
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
            string codeMarker = Path.Combine(current.FullName, "src", "Incursa.Quic.Dns", "DoqStream.cs");
            if ((Directory.Exists(gitMarker) || File.Exists(gitMarker)) && File.Exists(specMarker) && File.Exists(codeMarker))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Unable to locate the repository root for the RFC 9250 DoQ protocol-error tests.");
    }
}
