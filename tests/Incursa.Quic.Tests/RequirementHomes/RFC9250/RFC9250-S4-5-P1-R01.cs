// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9250-S4-5-P1-R01")]
public sealed class REQ_QUIC_RFC9250_0076
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void SessionResumptionAndZeroRttTraceArtifactsAreLinked()
    {
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-RFC9250.json");
        string architecture = ReadRepositoryFile("specs/architecture/quic/ARC-QUIC-RFC9250-0013.json");
        string workItem = ReadRepositoryFile("specs/work-items/quic/WI-QUIC-RFC9250-0013.json");
        string verification = ReadRepositoryFile("specs/verification/quic/VER-QUIC-RFC9250-0013.json");

        Assert.Contains("RFC9250-S4-5-P1-R01", spec, StringComparison.Ordinal);
        Assert.Contains("ARC-QUIC-RFC9250-0013", spec, StringComparison.Ordinal);
        Assert.Contains("WI-QUIC-RFC9250-0013", spec, StringComparison.Ordinal);
        Assert.Contains("VER-QUIC-RFC9250-0013", spec, StringComparison.Ordinal);
        Assert.Contains("RFC9250-S4-5-P1-R01", architecture, StringComparison.Ordinal);
        Assert.Contains("RFC9250-S4-5-P1-R01", workItem, StringComparison.Ordinal);
        Assert.Contains("RFC9250-S4-5-P1-R01", verification, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientPolicyAllowsOptInZeroRttForReplayableQueries()
    {
        string client = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqClient.cs");
        string serverOptions = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqServerOptions.cs");
        string tests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqStreamLifecycleTests.cs");

        Assert.Contains("public bool AllowZeroRtt { get; set; }", client, StringComparison.Ordinal);
        Assert.Contains("public TimeSpan ResumptionTicketLifetime", serverOptions, StringComparison.Ordinal);
        Assert.Contains("public bool EnableAntiReplay { get; set; } = true;", serverOptions, StringComparison.Ordinal);
        Assert.Contains("AllowsZeroRttForReplayableQueryOpcode", tests, StringComparison.Ordinal);
        Assert.Contains("client.AllowZeroRtt = true;", tests, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClientPolicyDoesNotUseZeroRttOrTicketsUnconditionally()
    {
        string client = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqClient.cs");
        string tests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqStreamLifecycleTests.cs");

        Assert.Contains("if (AllowZeroRtt && !DoqDefaults.IsReplayableQuery(query.Span))", client, StringComparison.Ordinal);
        Assert.Contains("if (IsTicketUsed)", client, StringComparison.Ordinal);
        Assert.Contains("RejectsZeroRttForNonReplayableOpcodeBeforeOpeningStream", tests, StringComparison.Ordinal);
        Assert.Contains("RejectsQueryWhenResumptionTicketIsAlreadyUsed", tests, StringComparison.Ordinal);
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
            if ((Directory.Exists(gitMarker) || File.Exists(gitMarker)) && File.Exists(specMarker))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Unable to locate the repository root for the RFC 9250 session resumption and 0-RTT tests.");
    }
}
