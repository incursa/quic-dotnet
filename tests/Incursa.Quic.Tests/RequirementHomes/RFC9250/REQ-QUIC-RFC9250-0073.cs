// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9250-0073")]
public sealed class REQ_QUIC_RFC9250_0073
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void OutstandingQueryNoErrorCloseTraceArtifactsAreLinked()
    {
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-RFC9250.json");
        string architecture = ReadRepositoryFile("specs/architecture/quic/ARC-QUIC-RFC9250-0011.json");
        string workItem = ReadRepositoryFile("specs/work-items/quic/WI-QUIC-RFC9250-0011.json");
        string verification = ReadRepositoryFile("specs/verification/quic/VER-QUIC-RFC9250-0011.json");

        Assert.Contains("REQ-QUIC-RFC9250-0073", spec, StringComparison.Ordinal);
        Assert.Contains("ARC-QUIC-RFC9250-0011", spec, StringComparison.Ordinal);
        Assert.Contains("WI-QUIC-RFC9250-0011", spec, StringComparison.Ordinal);
        Assert.Contains("VER-QUIC-RFC9250-0011", spec, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0073", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0073", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0073", verification, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void OutstandingQueryCloseUsesDoqNoError()
    {
        string errorCodes = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqErrorCode.cs");
        string client = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqClient.cs");
        string tests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqStreamLifecycleTests.cs");

        Assert.Contains("NoError = 0x0", errorCodes, StringComparison.Ordinal);
        Assert.Contains("targetConnection.CloseAsync((long)DoqErrorCode.NoError", client, StringComparison.Ordinal);
        Assert.Contains("DisposeAsyncWithOutstandingQueryClosesConnectionWithDoqNoError", tests, StringComparison.Ordinal);
        Assert.Contains("locallyProjectedNoError", tests, StringComparison.Ordinal);
        Assert.Contains("peerAcknowledgedNoErrorClose", tests, StringComparison.Ordinal);
        Assert.Contains("terminalState.Close.ApplicationErrorCode == (ulong)DoqErrorCode.NoError", tests, StringComparison.Ordinal);
        Assert.Contains("terminalState.Close.TransportErrorCode == QuicTransportErrorCode.NoError", tests, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void IdleClientDisposalDoesNotEmitDoqNoErrorClose()
    {
        string client = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqClient.cs");
        string tests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqStreamLifecycleTests.cs");

        Assert.Contains("if (ownsConnection && Volatile.Read(ref activeQueryCount) > 0)", client, StringComparison.Ordinal);
        Assert.Contains("DisposeAsyncWithoutOutstandingQueryDoesNotEmitDoqNoErrorClose", tests, StringComparison.Ordinal);
        Assert.Contains("terminalState.Value.Close.ApplicationErrorCode != (ulong)DoqErrorCode.NoError", tests, StringComparison.Ordinal);
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

        throw new InvalidOperationException("Unable to locate the repository root for the RFC 9250 outstanding-query no-error close tests.");
    }
}
