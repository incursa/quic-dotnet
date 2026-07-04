// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S12-2-P5-S2-R01">If decryption fails, the receiver MAY either discard or buffer the packet for later processing.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S12-2-P5-S2-R01")]
public sealed class REQ_QUIC_RFC9000_S12P2_0010
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryHandleHandshakePacketReceived_BuffersReplacementHandshakePacketsThatCannotBeOpenedYet()
    {
        using QuicConnectionRuntime clientRuntime = CreateClientRuntime(
            [0x11, 0x12, 0x13, 0x14],
            [0x21, 0x22, 0x23, 0x24]);

        QuicConnectionTransitionResult bootstrapResult = clientRuntime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: 0,
                LocalTransportParameters: QuicLoopbackEstablishmentTestSupport.CreateSupportedTransportParameters([0x21, 0x22, 0x23, 0x24])),
            nowTicks: 0);
        QuicConnectionSendDatagramEffect[] clientInitialDatagrams = bootstrapResult.Effects
            .OfType<QuicConnectionSendDatagramEffect>()
            .ToArray();
        Assert.NotEmpty(clientInitialDatagrams);

        ServerHandshakeFlight firstFlight = CreateServerHandshakeFlight(
            [0x11, 0x12, 0x13, 0x14],
            [0x21, 0x22, 0x23, 0x24],
            [0x31, 0x32, 0x33, 0x34],
            CreateScalar(0x21),
            clientInitialDatagrams);
        ServerHandshakeFlight replacementFlight = CreateServerHandshakeFlight(
            [0x11, 0x12, 0x13, 0x14],
            [0x21, 0x22, 0x23, 0x24],
            [0x41, 0x42, 0x43, 0x44],
            CreateScalar(0x22),
            clientInitialDatagrams);

        QuicConnectionTransitionResult firstInitialResult = clientRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 1,
                PathIdentity: BootstrapPath,
                Datagram: firstFlight.InitialPacket),
            nowTicks: 1);
        Assert.True(firstInitialResult.StateChanged);
        Assert.True(clientRuntime.CurrentPeerDestinationConnectionId.Span.SequenceEqual(new byte[] { 0x31, 0x32, 0x33, 0x34 }));

        QuicConnectionTransitionResult bufferedHandshakeResult = clientRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 2,
                PathIdentity: BootstrapPath,
                Datagram: replacementFlight.HandshakePacket),
            nowTicks: 2);

        Assert.Equal(1, GetBufferedEstablishmentHandshakePacketCount(clientRuntime));
        Assert.False(clientRuntime.PeerHandshakeTranscriptCompleted, DescribeState(clientRuntime, bufferedHandshakeResult));
        Assert.True(clientRuntime.Phase == QuicConnectionPhase.Establishing, DescribeState(clientRuntime, bufferedHandshakeResult));

        QuicConnectionTransitionResult replacementInitialResult = clientRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 3,
                PathIdentity: BootstrapPath,
                Datagram: replacementFlight.InitialPacket),
            nowTicks: 3);

        Assert.True(replacementInitialResult.StateChanged, DescribeState(clientRuntime, replacementInitialResult));
        Assert.Equal(0, GetBufferedEstablishmentHandshakePacketCount(clientRuntime));
        Assert.True(clientRuntime.Phase == QuicConnectionPhase.Active, DescribeState(clientRuntime, replacementInitialResult));
        Assert.True(clientRuntime.PeerHandshakeTranscriptCompleted, DescribeState(clientRuntime, replacementInitialResult));
        Assert.True(clientRuntime.TlsState.OneRttKeysAvailable, DescribeState(clientRuntime, replacementInitialResult));
        Assert.True(clientRuntime.CurrentPeerDestinationConnectionId.Span.SequenceEqual(new byte[] { 0x41, 0x42, 0x43, 0x44 }));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryHandleHandshakePacketReceived_DoesNotDeferSameAttemptHandshakePacketOpenFailuresForRetry()
    {
        using QuicConnectionRuntime clientRuntime = CreateClientRuntime(
            [0x51, 0x52, 0x53, 0x54],
            [0x61, 0x62, 0x63, 0x64]);

        QuicConnectionTransitionResult bootstrapResult = clientRuntime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: 0,
                LocalTransportParameters: QuicLoopbackEstablishmentTestSupport.CreateSupportedTransportParameters([0x61, 0x62, 0x63, 0x64])),
            nowTicks: 0);
        QuicConnectionSendDatagramEffect[] clientInitialDatagrams = bootstrapResult.Effects
            .OfType<QuicConnectionSendDatagramEffect>()
            .ToArray();
        Assert.NotEmpty(clientInitialDatagrams);

        ServerHandshakeFlight firstFlight = CreateServerHandshakeFlight(
            [0x51, 0x52, 0x53, 0x54],
            [0x61, 0x62, 0x63, 0x64],
            [0x71, 0x72, 0x73, 0x74],
            CreateScalar(0x31),
            clientInitialDatagrams);

        QuicConnectionTransitionResult firstInitialResult = clientRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 1,
                PathIdentity: BootstrapPath,
                Datagram: firstFlight.InitialPacket),
            nowTicks: 1);
        Assert.True(firstInitialResult.StateChanged);

        byte[] corruptedHandshakePacket = firstFlight.HandshakePacket.ToArray();
        corruptedHandshakePacket[^1] ^= 0x80;

        QuicConnectionTransitionResult corruptedHandshakeResult = clientRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 2,
                PathIdentity: BootstrapPath,
                Datagram: corruptedHandshakePacket),
            nowTicks: 2);

        Assert.Equal(0, GetBufferedEstablishmentHandshakePacketCount(clientRuntime));
        Assert.True(clientRuntime.Phase == QuicConnectionPhase.Establishing, DescribeState(clientRuntime, corruptedHandshakeResult));
        Assert.False(clientRuntime.PeerHandshakeTranscriptCompleted, DescribeState(clientRuntime, corruptedHandshakeResult));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryHandleHandshakePacketReceived_DoesNotBufferTheSameReplacementHandshakePacketTwice()
    {
        using QuicConnectionRuntime clientRuntime = CreateClientRuntime(
            [0x81, 0x82, 0x83, 0x84],
            [0x91, 0x92, 0x93, 0x94]);

        QuicConnectionTransitionResult bootstrapResult = clientRuntime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: 0,
                LocalTransportParameters: QuicLoopbackEstablishmentTestSupport.CreateSupportedTransportParameters([0x91, 0x92, 0x93, 0x94])),
            nowTicks: 0);
        QuicConnectionSendDatagramEffect[] clientInitialDatagrams = bootstrapResult.Effects
            .OfType<QuicConnectionSendDatagramEffect>()
            .ToArray();
        Assert.NotEmpty(clientInitialDatagrams);

        ServerHandshakeFlight firstFlight = CreateServerHandshakeFlight(
            [0x81, 0x82, 0x83, 0x84],
            [0x91, 0x92, 0x93, 0x94],
            [0xA1, 0xA2, 0xA3, 0xA4],
            CreateScalar(0x41),
            clientInitialDatagrams);
        ServerHandshakeFlight replacementFlight = CreateServerHandshakeFlight(
            [0x81, 0x82, 0x83, 0x84],
            [0x91, 0x92, 0x93, 0x94],
            [0xB1, 0xB2, 0xB3, 0xB4],
            CreateScalar(0x42),
            clientInitialDatagrams);

        QuicConnectionTransitionResult firstInitialResult = clientRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 1,
                PathIdentity: BootstrapPath,
                Datagram: firstFlight.InitialPacket),
            nowTicks: 1);
        Assert.True(firstInitialResult.StateChanged);

        QuicConnectionTransitionResult firstBufferResult = clientRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 2,
                PathIdentity: BootstrapPath,
                Datagram: replacementFlight.HandshakePacket),
            nowTicks: 2);
        QuicConnectionTransitionResult duplicateBufferResult = clientRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 3,
                PathIdentity: BootstrapPath,
                Datagram: replacementFlight.HandshakePacket),
            nowTicks: 3);

        Assert.Equal(1, GetBufferedEstablishmentHandshakePacketCount(clientRuntime));
        Assert.False(clientRuntime.PeerHandshakeTranscriptCompleted, DescribeState(clientRuntime, firstBufferResult));
        Assert.False(clientRuntime.PeerHandshakeTranscriptCompleted, DescribeState(clientRuntime, duplicateBufferResult));
    }

    private static readonly QuicConnectionPathIdentity BootstrapPath =
        new("203.0.113.30", "198.51.100.30", 443, 12345);

    private static QuicConnectionRuntime CreateClientRuntime(
        ReadOnlySpan<byte> initialDestinationConnectionId,
        ReadOnlySpan<byte> initialSourceConnectionId)
    {
        QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            remoteCertificateValidationCallback: static (_, _, _, errors) =>
                errors == SslPolicyErrors.RemoteCertificateChainErrors,
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
        Assert.True(runtime.TrySetBootstrapOutboundPath(BootstrapPath));
        Assert.True(runtime.TrySetHandshakeSourceConnectionId(initialSourceConnectionId));
        return runtime;
    }

    private static ServerHandshakeFlight CreateServerHandshakeFlight(
        ReadOnlySpan<byte> originalDestinationConnectionId,
        ReadOnlySpan<byte> initialSourceConnectionId,
        ReadOnlySpan<byte> serverSourceConnectionId,
        ReadOnlySpan<byte> localHandshakePrivateKey,
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
                    PathIdentity: BootstrapPath,
                    Datagram: clientInitialDatagram.Datagram),
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

    private static int GetBufferedEstablishmentHandshakePacketCount(QuicConnectionRuntime runtime)
    {
        return runtime.BufferedEstablishmentHandshakePacketCount;
    }

    private static string DescribeState(QuicConnectionRuntime runtime, QuicConnectionTransitionResult result)
    {
        return $"stateChanged={result.StateChanged}; phase={runtime.Phase}; peerHandshakeCompleted={runtime.PeerHandshakeTranscriptCompleted}; " +
               $"handshakeKeys={runtime.TlsState.HandshakeKeysAvailable}; oneRtt={runtime.TlsState.OneRttKeysAvailable}; " +
               $"bufferedHandshakePackets={GetBufferedEstablishmentHandshakePacketCount(runtime)}";
    }

    private static byte[] CreateScalar(byte lastByte)
    {
        byte[] scalar = new byte[32];
        scalar[^1] = lastByte;
        return scalar;
    }

    private sealed record ServerHandshakeFlight(byte[] InitialPacket, byte[] HandshakePacket);
}
