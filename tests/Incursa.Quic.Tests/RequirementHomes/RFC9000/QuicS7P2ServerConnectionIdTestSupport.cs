// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace Incursa.Quic.Tests;

internal static class QuicS7P2ServerConnectionIdTestSupport
{
    internal static readonly QuicConnectionPathIdentity BootstrapPath =
        new("203.0.113.30", "198.51.100.30", 443, 12345);

    internal static QuicConnectionRuntime CreateClientRuntime(
        ReadOnlySpan<byte> initialDestinationConnectionId,
        ReadOnlySpan<byte> initialSourceConnectionId,
        bool allowPeerInitialReplacement = false)
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
            allowClientPeerInitialReplacementBeforeTranscript: allowPeerInitialReplacement);

        Assert.True(runtime.TryConfigureInitialPacketProtection(initialDestinationConnectionId));
        Assert.True(runtime.TrySetBootstrapOutboundPath(BootstrapPath));
        Assert.True(runtime.TrySetHandshakeSourceConnectionId(initialSourceConnectionId));
        return runtime;
    }

    internal static QuicConnectionSendDatagramEffect[] BootstrapClient(
        QuicConnectionRuntime clientRuntime,
        ReadOnlySpan<byte> initialSourceConnectionId)
    {
        QuicConnectionTransitionResult bootstrapResult = clientRuntime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: 0,
                LocalTransportParameters: QuicLoopbackEstablishmentTestSupport.CreateSupportedTransportParameters(initialSourceConnectionId)),
            nowTicks: 0);

        QuicConnectionSendDatagramEffect[] clientInitialDatagrams = bootstrapResult.Effects
            .OfType<QuicConnectionSendDatagramEffect>()
            .ToArray();
        Assert.NotEmpty(clientInitialDatagrams);
        return clientInitialDatagrams;
    }

    internal static ServerHandshakeFlight CreateServerHandshakeFlight(
        ReadOnlySpan<byte> originalDestinationConnectionId,
        ReadOnlySpan<byte> initialSourceConnectionId,
        ReadOnlySpan<byte> serverSourceConnectionId,
        ReadOnlySpan<byte> localHandshakePrivateKey,
        IEnumerable<QuicConnectionSendDatagramEffect> clientInitialDatagrams)
    {
        return CreateServerHandshakeFlightCore(
            originalDestinationConnectionId,
            initialSourceConnectionId,
            serverSourceConnectionId,
            localHandshakePrivateKey,
            clientInitialDatagrams,
            initialPacketProtectionConnectionId: originalDestinationConnectionId,
            retrySourceConnectionId: ReadOnlySpan<byte>.Empty);
    }

    internal static ServerHandshakeFlight CreateServerHandshakeFlightAfterRetry(
        ReadOnlySpan<byte> originalDestinationConnectionId,
        ReadOnlySpan<byte> initialSourceConnectionId,
        ReadOnlySpan<byte> retrySourceConnectionId,
        ReadOnlySpan<byte> serverSourceConnectionId,
        ReadOnlySpan<byte> localHandshakePrivateKey,
        IEnumerable<QuicConnectionSendDatagramEffect> clientInitialDatagrams)
    {
        return CreateServerHandshakeFlightCore(
            originalDestinationConnectionId,
            initialSourceConnectionId,
            serverSourceConnectionId,
            localHandshakePrivateKey,
            clientInitialDatagrams,
            initialPacketProtectionConnectionId: retrySourceConnectionId,
            retrySourceConnectionId: retrySourceConnectionId);
    }

    private static ServerHandshakeFlight CreateServerHandshakeFlightCore(
        ReadOnlySpan<byte> originalDestinationConnectionId,
        ReadOnlySpan<byte> initialSourceConnectionId,
        ReadOnlySpan<byte> serverSourceConnectionId,
        ReadOnlySpan<byte> localHandshakePrivateKey,
        IEnumerable<QuicConnectionSendDatagramEffect> clientInitialDatagrams,
        ReadOnlySpan<byte> initialPacketProtectionConnectionId,
        ReadOnlySpan<byte> retrySourceConnectionId)
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
        if (!retrySourceConnectionId.IsEmpty)
        {
            serverTransportParameters.RetrySourceConnectionId = retrySourceConnectionId.ToArray();
        }

        Assert.True(serverRuntime.TryConfigureInitialPacketProtection(initialPacketProtectionConnectionId));
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
                    BootstrapPath,
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

    internal static QuicConnectionTransitionResult ReceivePacket(
        QuicConnectionRuntime runtime,
        ReadOnlyMemory<byte> datagram,
        long observedAtTicks)
    {
        return runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: observedAtTicks,
                BootstrapPath,
                datagram),
            nowTicks: observedAtTicks);
    }

    internal static byte[] BuildZeroRttPacketAfterServerSourceConnectionIdAdoption(
        ReadOnlySpan<byte> initialDestinationConnectionId,
        ReadOnlySpan<byte> initialSourceConnectionId,
        ReadOnlySpan<byte> serverSourceConnectionId)
    {
        QuicHandshakeFlowCoordinator coordinator = new(
            initialDestinationConnectionId.ToArray(),
            initialSourceConnectionId.ToArray());
        Assert.True(coordinator.TrySetHandshakeDestinationConnectionId(serverSourceConnectionId));

        QuicTlsPacketProtectionMaterial zeroRttMaterial =
            QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(QuicTlsEncryptionLevel.ZeroRtt);
        Assert.True(coordinator.TryBuildProtectedZeroRttApplicationPacket(
            QuicS17P2P3TestSupport.CreatePingPayload(),
            zeroRttMaterial,
            out _,
            out byte[] zeroRttPacket));
        return zeroRttPacket;
    }

    internal static int GetBufferedEstablishmentHandshakePacketCount(QuicConnectionRuntime runtime)
    {
        return runtime.BufferedEstablishmentHandshakePacketCount;
    }

    internal static byte[] CreateScalar(byte lastByte)
    {
        byte[] scalar = new byte[32];
        scalar[^1] = lastByte;
        return scalar;
    }

    internal static void AssertLongHeaderConnectionIds(
        ReadOnlySpan<byte> datagram,
        ReadOnlySpan<byte> expectedDestinationConnectionId,
        ReadOnlySpan<byte> expectedSourceConnectionId)
    {
        Assert.True(QuicPacketParser.TryParseLongHeader(datagram, out QuicLongHeaderPacket header));
        Assert.True(header.DestinationConnectionId.SequenceEqual(expectedDestinationConnectionId));
        Assert.True(header.SourceConnectionId.SequenceEqual(expectedSourceConnectionId));
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
                ReadOnlyMemory<byte> remainingDatagram = sendEffect.Datagram[packetOffset..];
                Assert.True(QuicPacketParser.TryGetPacketLength(remainingDatagram.Span, out int packetLength));
                ReadOnlyMemory<byte> packet = remainingDatagram[..packetLength];
                if (QuicPacketParser.TryGetPacketNumberSpace(packet.Span, out QuicPacketNumberSpace observedPacketNumberSpace)
                    && observedPacketNumberSpace == packetNumberSpace)
                {
                    return packet.ToArray();
                }

                packetOffset += packetLength;
            }
        }

        return null;
    }
}

internal readonly record struct ServerHandshakeFlight(
    byte[] InitialPacket,
    byte[] HandshakePacket);
