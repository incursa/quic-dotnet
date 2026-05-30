// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9250-0001")]
[Requirement("REQ-QUIC-RFC9250-0003")]
[Requirement("REQ-QUIC-RFC9250-0126")]
[Requirement("REQ-QUIC-RFC9250-0127")]
[Requirement("REQ-QUIC-RFC9250-0128")]
[Requirement("REQ-QUIC-RFC9250-0129")]
[Requirement("REQ-QUIC-RFC9250-0130")]
[Requirement("REQ-QUIC-RFC9250-0131")]
[Requirement("REQ-QUIC-RFC9250-0132")]
[Requirement("REQ-QUIC-RFC9250-0133")]
public sealed class REQ_QUIC_RFC9250_0022
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DoqSectionThreeAndRegistryTraceArtifactsAreLinked()
    {
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-RFC9250.json");
        string architecture = ReadRepositoryFile("specs/architecture/quic/ARC-QUIC-RFC9250-0022.json");
        string workItem = ReadRepositoryFile("specs/work-items/quic/WI-QUIC-RFC9250-0022.json");
        string verification = ReadRepositoryFile("specs/verification/quic/VER-QUIC-RFC9250-0022.json");

        Assert.Contains("ARC-QUIC-RFC9250-0022", spec, StringComparison.Ordinal);
        Assert.Contains("WI-QUIC-RFC9250-0022", spec, StringComparison.Ordinal);
        Assert.Contains("VER-QUIC-RFC9250-0022", spec, StringComparison.Ordinal);

        string[] requirementIds =
        [
            "REQ-QUIC-RFC9250-0001",
            "REQ-QUIC-RFC9250-0003",
            "REQ-QUIC-RFC9250-0126",
            "REQ-QUIC-RFC9250-0127",
            "REQ-QUIC-RFC9250-0128",
            "REQ-QUIC-RFC9250-0129",
            "REQ-QUIC-RFC9250-0130",
            "REQ-QUIC-RFC9250-0131",
            "REQ-QUIC-RFC9250-0132",
            "REQ-QUIC-RFC9250-0133",
        ];

        foreach (string requirementId in requirementIds)
        {
            Assert.Contains(requirementId, spec, StringComparison.Ordinal);
            Assert.Contains(requirementId, architecture, StringComparison.Ordinal);
            Assert.Contains(requirementId, workItem, StringComparison.Ordinal);
            Assert.Contains(requirementId, verification, StringComparison.Ordinal);
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DoqSectionThreeResidueUsesStreamTransportInsteadOfDatagramApis()
    {
        string client = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqClient.cs");
        string server = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqServer.cs");
        string stream = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqStream.cs");
        string lifecycleTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqStreamLifecycleTests.cs");

        Assert.Contains("OpenOutboundStreamAsync(QuicStreamType.Bidirectional", client, StringComparison.Ordinal);
        Assert.Contains("AcceptInboundStreamAsync", server, StringComparison.Ordinal);
        Assert.Contains("LargeDnsResponsesFlowThroughTheDoqStreamPath", lifecycleTests, StringComparison.Ordinal);
        Assert.DoesNotContain("SendDatagram", client, StringComparison.Ordinal);
        Assert.DoesNotContain("ReceiveDatagram", client, StringComparison.Ordinal);
        Assert.DoesNotContain("SendDatagram", server, StringComparison.Ordinal);
        Assert.DoesNotContain("ReceiveDatagram", server, StringComparison.Ordinal);
        Assert.DoesNotContain("QuicDatagram", stream, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DoqTlsNegotiationIsTraceLinkedToTransportHostConfiguration()
    {
        string clientHost = ReadRepositoryFile("src/Incursa.Quic/QuicClientConnectionHost.cs");
        string listenerOptions = ReadRepositoryFile("src/Incursa.Quic/QuicListenerOptions.cs");
        string listenerHost = ReadRepositoryFile("src/Incursa.Quic/QuicListenerHost.cs");
        string defaults = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqDefaults.cs");
        string foundationTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqFoundationTests.cs");

        Assert.Contains("ClientAuthenticationOptions", clientHost, StringComparison.Ordinal);
        Assert.Contains("ServerAuthenticationOptions", listenerHost, StringComparison.Ordinal);
        Assert.Contains("ConnectionOptionsCallback", listenerOptions, StringComparison.Ordinal);
        Assert.Contains("ApplicationProtocols", defaults, StringComparison.Ordinal);
        Assert.Contains("ApplicationProtocol", defaults, StringComparison.Ordinal);
        Assert.Contains("ApplicationProtocolUsesDoqAlpn", foundationTests, StringComparison.Ordinal);
        Assert.Contains("AlpnByteSequenceMatchesDoqDefaultsAlpn", foundationTests, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DoqTlsNegotiationStaysInTheTransportLayer()
    {
        string client = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqClient.cs");
        string server = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqServer.cs");
        string stream = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqStream.cs");
        string listenerOptions = ReadRepositoryFile("src/Incursa.Quic/QuicListenerOptions.cs");
        string clientHost = ReadRepositoryFile("src/Incursa.Quic/QuicClientConnectionHost.cs");
        string listenerHost = ReadRepositoryFile("src/Incursa.Quic/QuicListenerHost.cs");
        string defaults = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqDefaults.cs");

        Assert.DoesNotContain("SslStream", client, StringComparison.Ordinal);
        Assert.DoesNotContain("SslStream", server, StringComparison.Ordinal);
        Assert.DoesNotContain("SslStream", stream, StringComparison.Ordinal);
        Assert.DoesNotContain("TcpClient", client, StringComparison.Ordinal);
        Assert.DoesNotContain("TcpClient", server, StringComparison.Ordinal);
        Assert.DoesNotContain("TcpClient", stream, StringComparison.Ordinal);
        Assert.Contains("ClientAuthenticationOptions", clientHost, StringComparison.Ordinal);
        Assert.Contains("ServerAuthenticationOptions", listenerHost, StringComparison.Ordinal);
        Assert.Contains("ConnectionOptionsCallback", listenerOptions, StringComparison.Ordinal);
        Assert.Contains("ApplicationProtocols", defaults, StringComparison.Ordinal);
        Assert.Contains("ApplicationProtocol", defaults, StringComparison.Ordinal);
        Assert.Contains("AlpnToken = \"doq\"", defaults, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DoqAlpnAndRegistryGovernanceAreTraceLinked()
    {
        string defaults = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqDefaults.cs");
        string errorCodes = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqErrorCode.cs");
        string foundationTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqFoundationTests.cs");
        string fatalTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqFatalProtocolErrorTests.cs");
        string architecture = ReadRepositoryFile("specs/architecture/quic/ARC-QUIC-RFC9250-0022.json");

        Assert.Contains("Alpn => \"doq\"u8", defaults, StringComparison.Ordinal);
        Assert.Contains("AlpnByteSequenceMatchesDoqDefaultsAlpn", foundationTests, StringComparison.Ordinal);
        Assert.Contains("ErrorCodeValuesMatchRfc9250Registry", foundationTests, StringComparison.Ordinal);
        Assert.Contains("NormalizeReceivedErrorCode_MapsUnknownCodesToUnspecifiedError", fatalTests, StringComparison.Ordinal);
        Assert.Contains("NormalizeReceivedErrorCode_PassesThroughKnownCodes", fatalTests, StringComparison.Ordinal);
        Assert.Contains("62-bit", architecture, StringComparison.Ordinal);
        Assert.Contains("Standards Action", architecture, StringComparison.Ordinal);
        Assert.Contains("IESG Approval", architecture, StringComparison.Ordinal);
        Assert.Contains("Specification Required", architecture, StringComparison.Ordinal);
        Assert.Contains("Expert Review", architecture, StringComparison.Ordinal);
        Assert.Contains("IANA registry", errorCodes, StringComparison.Ordinal);
        Assert.Contains("UnspecifiedError", errorCodes, StringComparison.Ordinal);
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

        throw new InvalidOperationException("Unable to locate the repository root for the RFC 9250 DoQ section-3 and registry tests.");
    }
}
