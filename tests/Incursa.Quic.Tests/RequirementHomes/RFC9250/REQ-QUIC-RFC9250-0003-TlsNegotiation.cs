// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9250_0003_TLS
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0003")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DoqTlsNegotiationTraceArtifactsAreLinked()
    {
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-RFC9250.json");
        string architecture = ReadRepositoryFile("specs/architecture/quic/ARC-QUIC-RFC9250-0022.json");
        string workItem = ReadRepositoryFile("specs/work-items/quic/WI-QUIC-RFC9250-0022.json");
        string verification = ReadRepositoryFile("specs/verification/quic/VER-QUIC-RFC9250-0022.json");

        Assert.Contains("REQ-QUIC-RFC9250-0003", spec, StringComparison.Ordinal);
        Assert.Contains("ARC-QUIC-RFC9250-0022", spec, StringComparison.Ordinal);
        Assert.Contains("WI-QUIC-RFC9250-0022", spec, StringComparison.Ordinal);
        Assert.Contains("VER-QUIC-RFC9250-0022", spec, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0003", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0003", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0003", verification, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0003")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DoqClientSetupRequiresTlsAuthenticationCarrier()
    {
        string defaults = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqDefaults.cs");
        string clientHost = ReadRepositoryFile("src/Incursa.Quic/QuicClientConnectionHost.cs");
        string listenerHost = ReadRepositoryFile("src/Incursa.Quic/QuicListenerHost.cs");
        string tests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqFoundationTests.cs");

        Assert.Contains("SslClientAuthenticationOptions authenticationOptions", defaults, StringComparison.Ordinal);
        Assert.Contains("ClientAuthenticationOptions", clientHost, StringComparison.Ordinal);
        Assert.Contains("ServerAuthenticationOptions", listenerHost, StringComparison.Ordinal);
        Assert.Contains("ClientOptionsCarryTlsAuthenticationOptionsForDoqSetup", tests, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0003")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DoqClientSetupRejectsMissingTlsAuthenticationCarrier()
    {
        string defaults = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqDefaults.cs");
        string tests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqFoundationTests.cs");

        Assert.Contains("DoQ client authentication options are required", defaults, StringComparison.Ordinal);
        Assert.Contains("ClientOptionsRejectMissingTlsAuthenticationOptionsForDoqSetup", tests, StringComparison.Ordinal);
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

        throw new InvalidOperationException("Unable to locate the repository root for the RFC 9250 DoQ TLS negotiation tests.");
    }
}
