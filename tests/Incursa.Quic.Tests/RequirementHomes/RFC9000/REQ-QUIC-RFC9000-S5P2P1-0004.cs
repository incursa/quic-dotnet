// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S5P2P1-0004")]
public sealed class REQ_QUIC_RFC9000_S5P2P1_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ReplacementHandshakePacketsCanBeBufferedUntilTheMatchingReplacementInitialArrives()
    {
        // Provenance:
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260421-180141270-client-chrome\
        //   runner-logs\quic-go_chrome\handshakeloss\client\qlog\client-multiconnect-3b891db978f74293ad0ce8ec2fe178e5.qlog
        //   runner-logs\quic-go_chrome\handshakeloss\server\log.txt
        // The stalled client-role quic-go multiconnect connection first accepted server attempt
        // 2310e7da, then received replacement Handshake packets from fd0f0e4a before a later
        // replacement Initial from that same source CID. RFC 9000 allows the client to buffer
        // packets encrypted with keys it has not yet computed; this proof keeps the slice narrow
        // by replaying those buffered replacement Handshake packets only after the replacement
        // Initial rederives the matching Handshake-open material.
        byte[] originalDestinationConnectionId = [0x11, 0x12, 0x13, 0x14];
        byte[] clientSourceConnectionId = [0x21, 0x22, 0x23, 0x24];
        byte[] firstServerSourceConnectionId = [0x31, 0x32, 0x33, 0x34];
        byte[] replacementServerSourceConnectionId = [0x41, 0x42, 0x43, 0x44];
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.10", "198.51.100.20", 443, 12345);

        using QuicConnectionRuntime clientRuntime = CreateClientRuntime(
            originalDestinationConnectionId,
            clientSourceConnectionId);

        QuicConnectionTransitionResult bootstrapResult = clientRuntime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: 0,
                LocalTransportParameters: QuicLoopbackEstablishmentTestSupport.CreateSupportedTransportParameters(clientSourceConnectionId)),
            nowTicks: 0);
        QuicConnectionSendDatagramEffect[] clientInitialDatagrams = bootstrapResult.Effects
            .OfType<QuicConnectionSendDatagramEffect>()
            .ToArray();
        Assert.NotEmpty(clientInitialDatagrams);

        ServerHandshakeFlight firstFlight = CreateServerHandshakeFlight(
            originalDestinationConnectionId,
            clientSourceConnectionId,
            firstServerSourceConnectionId,
            CreateScalar(0x21),
            pathIdentity,
            clientInitialDatagrams);
        ServerHandshakeFlight replacementFlight = CreateServerHandshakeFlight(
            originalDestinationConnectionId,
            clientSourceConnectionId,
            replacementServerSourceConnectionId,
            CreateScalar(0x22),
            pathIdentity,
            clientInitialDatagrams);

        QuicConnectionTransitionResult firstInitialResult = clientRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 1,
                pathIdentity,
                firstFlight.InitialPacket),
            nowTicks: 1);
        Assert.True(firstInitialResult.StateChanged, DescribeState(clientRuntime, firstInitialResult));
        Assert.True(
            clientRuntime.CurrentPeerDestinationConnectionId.Span.SequenceEqual(firstServerSourceConnectionId),
            DescribeState(clientRuntime, firstInitialResult));

        QuicConnectionTransitionResult bufferedHandshakeResult = clientRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 2,
                pathIdentity,
                replacementFlight.HandshakePacket),
            nowTicks: 2);
        Assert.Equal(1, GetBufferedEstablishmentHandshakePacketCount(clientRuntime));
        Assert.False(clientRuntime.PeerHandshakeTranscriptCompleted, DescribeState(clientRuntime, bufferedHandshakeResult));
        Assert.True(clientRuntime.Phase == QuicConnectionPhase.Establishing, DescribeState(clientRuntime, bufferedHandshakeResult));

        QuicConnectionTransitionResult replacementInitialResult = clientRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 3,
                pathIdentity,
                replacementFlight.InitialPacket),
            nowTicks: 3);

        Assert.True(replacementInitialResult.StateChanged, DescribeState(clientRuntime, replacementInitialResult));
        Assert.Equal(0, GetBufferedEstablishmentHandshakePacketCount(clientRuntime));
        Assert.True(clientRuntime.Phase == QuicConnectionPhase.Active, DescribeState(clientRuntime, replacementInitialResult));
        Assert.True(clientRuntime.PeerHandshakeTranscriptCompleted, DescribeState(clientRuntime, replacementInitialResult));
        Assert.True(clientRuntime.TlsState.OneRttKeysAvailable, DescribeState(clientRuntime, replacementInitialResult));
        Assert.True(
            clientRuntime.CurrentPeerDestinationConnectionId.Span.SequenceEqual(replacementServerSourceConnectionId),
            DescribeState(clientRuntime, replacementInitialResult));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void CurrentAttemptHandshakeOpenFailuresAreNotDeferredForRetry()
    {
        // Provenance:
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260421-180141270-client-chrome\
        //   runner-logs\quic-go_chrome\handshakeloss\client\qlog\client-multiconnect-3b891db978f74293ad0ce8ec2fe178e5.qlog
        // The live failure hinged on a replacement-attempt source-CID change before the client had
        // the matching replacement Initial. This negative keeps the buffering scope bounded: a
        // Handshake packet that still claims the current attempt source CID remains droppable, and
        // the runtime must not retain it for deferred replay.
        byte[] originalDestinationConnectionId = [0x51, 0x52, 0x53, 0x54];
        byte[] clientSourceConnectionId = [0x61, 0x62, 0x63, 0x64];
        byte[] firstServerSourceConnectionId = [0x71, 0x72, 0x73, 0x74];
        byte[] replacementServerSourceConnectionId = [0x81, 0x82, 0x83, 0x84];
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.11", "198.51.100.21", 443, 12346);

        using QuicConnectionRuntime clientRuntime = CreateClientRuntime(
            originalDestinationConnectionId,
            clientSourceConnectionId);

        QuicConnectionTransitionResult bootstrapResult = clientRuntime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: 0,
                LocalTransportParameters: QuicLoopbackEstablishmentTestSupport.CreateSupportedTransportParameters(clientSourceConnectionId)),
            nowTicks: 0);
        QuicConnectionSendDatagramEffect[] clientInitialDatagrams = bootstrapResult.Effects
            .OfType<QuicConnectionSendDatagramEffect>()
            .ToArray();
        Assert.NotEmpty(clientInitialDatagrams);

        ServerHandshakeFlight firstFlight = CreateServerHandshakeFlight(
            originalDestinationConnectionId,
            clientSourceConnectionId,
            firstServerSourceConnectionId,
            CreateScalar(0x31),
            pathIdentity,
            clientInitialDatagrams);
        ServerHandshakeFlight replacementFlight = CreateServerHandshakeFlight(
            originalDestinationConnectionId,
            clientSourceConnectionId,
            replacementServerSourceConnectionId,
            CreateScalar(0x32),
            pathIdentity,
            clientInitialDatagrams);

        QuicConnectionTransitionResult firstInitialResult = clientRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 1,
                pathIdentity,
                firstFlight.InitialPacket),
            nowTicks: 1);
        Assert.True(firstInitialResult.StateChanged, DescribeState(clientRuntime, firstInitialResult));
        Assert.True(
            clientRuntime.CurrentPeerDestinationConnectionId.Span.SequenceEqual(firstServerSourceConnectionId),
            DescribeState(clientRuntime, firstInitialResult));

        byte[] sameAttemptCorruptedHandshakePacket = RewriteLongHeaderSourceConnectionId(
            replacementFlight.HandshakePacket,
            firstServerSourceConnectionId);
        QuicConnectionTransitionResult corruptedHandshakeResult = clientRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 2,
                pathIdentity,
                sameAttemptCorruptedHandshakePacket),
            nowTicks: 2);
        Assert.Equal(0, GetBufferedEstablishmentHandshakePacketCount(clientRuntime));
        Assert.True(clientRuntime.Phase == QuicConnectionPhase.Establishing, DescribeState(clientRuntime, corruptedHandshakeResult));
        Assert.False(clientRuntime.PeerHandshakeTranscriptCompleted, DescribeState(clientRuntime, corruptedHandshakeResult));

        QuicConnectionTransitionResult firstHandshakeResult = clientRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 3,
                pathIdentity,
                firstFlight.HandshakePacket),
            nowTicks: 3);
        Assert.True(firstHandshakeResult.StateChanged, DescribeState(clientRuntime, firstHandshakeResult));
        Assert.True(clientRuntime.Phase == QuicConnectionPhase.Active, DescribeState(clientRuntime, firstHandshakeResult));
        Assert.True(clientRuntime.PeerHandshakeTranscriptCompleted, DescribeState(clientRuntime, firstHandshakeResult));
    }

    private static QuicConnectionRuntime CreateClientRuntime(
        ReadOnlySpan<byte> initialDestinationConnectionId,
        ReadOnlySpan<byte> initialSourceConnectionId)
    {
        QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            remoteCertificateValidationCallback: static (_, _, _, errors) => errors == SslPolicyErrors.RemoteCertificateChainErrors,
            clientAuthenticationOptions: new SslClientAuthenticationOptions
            {
                AllowRenegotiation = false,
                AllowTlsResume = true,
                ApplicationProtocols = [SslApplicationProtocol.Http3],
                EnabledSslProtocols = SslProtocols.Tls13,
                EncryptionPolicy = EncryptionPolicy.RequireEncryption,
                TargetHost = "server4",
            },
            tlsRole: QuicTlsRole.Client,
            allowClientPeerInitialReplacementBeforeTranscript: true);

        Assert.True(runtime.TryConfigureInitialPacketProtection(initialDestinationConnectionId));
        Assert.True(runtime.TrySetBootstrapOutboundPath(new QuicConnectionPathIdentity("203.0.113.1", "198.51.100.1", 443, 12345)));
        Assert.True(runtime.TrySetHandshakeSourceConnectionId(initialSourceConnectionId));
        return runtime;
    }

    private static ServerHandshakeFlight CreateServerHandshakeFlight(
        ReadOnlySpan<byte> originalDestinationConnectionId,
        ReadOnlySpan<byte> initialSourceConnectionId,
        ReadOnlySpan<byte> serverSourceConnectionId,
        ReadOnlySpan<byte> localHandshakePrivateKey,
        QuicConnectionPathIdentity pathIdentity,
        IEnumerable<QuicConnectionSendDatagramEffect> clientInitialDatagrams)
    {
        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate("server4");
        QuicServerConnectionSettings serverSettings = QuicServerConnectionOptionsValidator.Capture(
            QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate),
            parameterName: "serverOptions",
            listenerApplicationProtocols: [SslApplicationProtocol.Http3]);

        using QuicConnectionRuntime serverRuntime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            localHandshakePrivateKey: localHandshakePrivateKey.ToArray(),
            tlsRole: QuicTlsRole.Server);
        QuicTransportParameters serverTransportParameters =
            QuicLoopbackEstablishmentTestSupport.CreateSupportedTransportParameters(serverSourceConnectionId);
        serverTransportParameters.OriginalDestinationConnectionId = originalDestinationConnectionId.ToArray();
        Assert.True(serverRuntime.TryConfigureInitialPacketProtection(originalDestinationConnectionId));
        Assert.True(serverRuntime.TrySetHandshakeDestinationConnectionId(initialSourceConnectionId));
        Assert.True(serverRuntime.TrySetHandshakeSourceConnectionId(serverSourceConnectionId));
        Assert.True(serverRuntime.TryConfigureServerAuthenticationMaterial(
            serverSettings.ServerLeafCertificateDer,
            serverSettings.ServerLeafSigningPrivateKey));
        Assert.True(serverRuntime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: 0,
                LocalTransportParameters: serverTransportParameters),
            nowTicks: 0).StateChanged);

        byte[]? initialPacket = null;
        byte[]? handshakePacket = null;
        long observedAtTicks = 1;
        foreach (QuicConnectionSendDatagramEffect clientInitialDatagram in clientInitialDatagrams)
        {
            QuicConnectionTransitionResult serverResult = serverRuntime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: observedAtTicks,
                    pathIdentity,
                    clientInitialDatagram.Datagram),
                nowTicks: observedAtTicks);

            initialPacket ??= TryExtractFirstPacketBySpace(serverResult.Effects, QuicPacketNumberSpace.Initial);
            handshakePacket ??= TryExtractFirstPacketBySpace(serverResult.Effects, QuicPacketNumberSpace.Handshake);
            if (initialPacket is not null && handshakePacket is not null)
            {
                break;
            }

            observedAtTicks++;
        }

        Assert.NotNull(initialPacket);
        Assert.NotNull(handshakePacket);
        return new ServerHandshakeFlight(initialPacket!, handshakePacket!);
    }

    private static byte[]? TryExtractFirstPacketBySpace(
        IEnumerable<QuicConnectionEffect> effects,
        QuicPacketNumberSpace packetNumberSpace)
    {
        foreach (QuicConnectionSendDatagramEffect sendEffect in effects.OfType<QuicConnectionSendDatagramEffect>())
        {
            int packetOffset = 0;
            while (packetOffset < sendEffect.Datagram.Length)
            {
                ReadOnlySpan<byte> remaining = sendEffect.Datagram.Span[packetOffset..];
                if (!QuicPacketParser.TryGetPacketLength(remaining, out int packetLength) || packetLength <= 0)
                {
                    break;
                }

                ReadOnlySpan<byte> packet = remaining[..packetLength];
                if (QuicPacketParser.TryGetPacketNumberSpace(packet, out QuicPacketNumberSpace packetSpace)
                    && packetSpace == packetNumberSpace)
                {
                    return packet.ToArray();
                }

                packetOffset += packetLength;
            }
        }

        return null;
    }

    private static byte[] RewriteLongHeaderSourceConnectionId(
        ReadOnlySpan<byte> packet,
        ReadOnlySpan<byte> replacementSourceConnectionId)
    {
        byte[] mutatedPacket = packet.ToArray();
        int destinationConnectionIdLengthOffset = 1 + sizeof(uint);
        int destinationConnectionIdLength = mutatedPacket[destinationConnectionIdLengthOffset];
        int sourceConnectionIdLengthOffset = destinationConnectionIdLengthOffset + 1 + destinationConnectionIdLength;
        int sourceConnectionIdLength = mutatedPacket[sourceConnectionIdLengthOffset];

        Assert.Equal(sourceConnectionIdLength, replacementSourceConnectionId.Length);
        replacementSourceConnectionId.CopyTo(
            mutatedPacket.AsSpan(sourceConnectionIdLengthOffset + 1, sourceConnectionIdLength));
        return mutatedPacket;
    }

    private static int GetBufferedEstablishmentHandshakePacketCount(QuicConnectionRuntime runtime)
    {
        return runtime.BufferedEstablishmentHandshakePacketCount;
    }

    private static string DescribeState(
        QuicConnectionRuntime runtime,
        QuicConnectionTransitionResult result)
    {
        return $"stateChanged={result.StateChanged}; phase={runtime.Phase}; peerHandshakeCompleted={runtime.PeerHandshakeTranscriptCompleted}; " +
               $"handshakeKeys={runtime.TlsState.HandshakeKeysAvailable}; oneRtt={runtime.TlsState.OneRttKeysAvailable}; " +
               $"bufferedHandshakePackets={GetBufferedEstablishmentHandshakePacketCount(runtime)}";
    }

    private sealed record ServerHandshakeFlight(byte[] InitialPacket, byte[] HandshakePacket);

    private static byte[] CreateScalar(byte lastByte)
    {
        byte[] scalar = new byte[32];
        scalar[^1] = lastByte;
        return scalar;
    }
}
