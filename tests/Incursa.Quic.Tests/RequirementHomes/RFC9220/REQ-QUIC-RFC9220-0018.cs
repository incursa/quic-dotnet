// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9220-0017")]
[Requirement("REQ-QUIC-RFC9220-0018")]
[Requirement("REQ-QUIC-RFC9220-0019")]
[Requirement("REQ-QUIC-RFC9220-0022")]
[Requirement("REQ-QUIC-RFC9220-0030")]
[Requirement("REQ-QUIC-RFC9220-0031")]
public sealed class REQ_QUIC_RFC9220_0018
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void WebSocketPeerProofHarnessRecordsLocalAndExternalAioquicEvidence()
    {
        string architecture = ReadRepositoryFile("specs/architecture/quic/ARC-QUIC-RFC9220-0018.json");
        string workItem = ReadRepositoryFile("specs/work-items/quic/WI-QUIC-RFC9220-0018.json");
        string verification = ReadRepositoryFile("specs/verification/quic/VER-QUIC-RFC9220-0018.json");
        string gapLedger = ReadRepositoryFile("specs/requirements/quic/REQUIREMENT-GAPS.md");
        string status = ReadRepositoryFile("docs/current-status.md");
        string proofScript = ReadRepositoryFile("scripts/proofs/Invoke-Rfc9220WebSocketExternalAioquicProof.ps1");
        string dockerfile = ReadRepositoryFile("scripts/interop/http3-external/docker/aioquic.Dockerfile");
        string aioquicClient = ReadRepositoryFile("scripts/interop/http3-external/docker/aioquic_http3_websocket_client.py");

        Assert.Contains("Invoke-Rfc9220WebSocketExternalAioquicProof.ps1", architecture, StringComparison.Ordinal);
        Assert.Contains("aioquic_http3_websocket_client.py", architecture, StringComparison.Ordinal);
        Assert.Contains("local-external-aioquic-peer", architecture, StringComparison.Ordinal);
        Assert.Contains("local-external-aioquic-peer", verification, StringComparison.Ordinal);
        Assert.Contains("http3-websocket-external-aioquic", verification, StringComparison.Ordinal);
        Assert.Contains("20260619T-rfc9220-aioquic-001", workItem, StringComparison.Ordinal);
        Assert.Contains("20260619T-rfc9220-aioquic-001", gapLedger, StringComparison.Ordinal);
        Assert.Contains("20260619T-rfc9220-aioquic-001", status, StringComparison.Ordinal);

        Assert.Contains("aioquic-http3-websocket-client", proofScript, StringComparison.Ordinal);
        Assert.Contains("QLOGDIR=/proof/client-qlog", proofScript, StringComparison.Ordinal);
        Assert.Contains("SSLKEYLOGFILE=/proof/client-sslkeylog/keys.log", proofScript, StringComparison.Ordinal);
        Assert.Contains("host.docker.internal", proofScript, StringComparison.Ordinal);
        Assert.Contains("aioquic_http3_websocket_client.py", dockerfile, StringComparison.Ordinal);
        Assert.Contains("aioquic-http3-websocket-client", dockerfile, StringComparison.Ordinal);

        Assert.Contains("(b\":method\", b\"CONNECT\")", aioquicClient, StringComparison.Ordinal);
        Assert.Contains("(b\":protocol\", b\"websocket\")", aioquicClient, StringComparison.Ordinal);
        Assert.Contains("sec-websocket-protocol", aioquicClient, StringComparison.Ordinal);
        Assert.Contains("OPCODE_PING", aioquicClient, StringComparison.Ordinal);
        Assert.Contains("OPCODE_CLOSE", aioquicClient, StringComparison.Ordinal);
        Assert.Contains("masked=True", aioquicClient, StringComparison.Ordinal);
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
            string specMarker = Path.Combine(current.FullName, "specs", "requirements", "quic", "SPEC-QUIC-RFC9220.json");
            string sourceMarker = Path.Combine(current.FullName, "src", "Incursa.Quic.Http3", "Http3Server.cs");
            if ((Directory.Exists(gitMarker) || File.Exists(gitMarker)) && File.Exists(specMarker) && File.Exists(sourceMarker))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Unable to locate repository root.");
    }
}
