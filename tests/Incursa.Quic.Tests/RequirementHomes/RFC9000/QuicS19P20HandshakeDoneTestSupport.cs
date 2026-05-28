// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

internal static class QuicS19P20HandshakeDoneTestSupport
{
    private static readonly byte[] InitialDestinationConnectionId =
    [
        0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08,
    ];

    internal static readonly QuicConnectionPathIdentity PacketPathIdentity =
        new("203.0.113.10", "198.51.100.20", 443, 12345);

    internal static QuicConnectionRuntime CreateServerRuntimeReadyToEvaluateHandshakeDoneSend()
    {
        QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(isServer: true),
            new FakeMonotonicClock(0),
            tlsRole: QuicTlsRole.Server,
            localHandshakePrivateKey: CreateScalar(0x11));

        Assert.True(runtime.TrySetHandshakeDestinationConnectionId(InitialDestinationConnectionId));
        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 0,
                PacketPathIdentity,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 0).StateChanged);

        QuicTransportParameters peerTransportParameters = new()
        {
            InitialSourceConnectionId = [0x0A, 0x0B, 0x0C],
        };

        Assert.True(runtime.TlsState.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.TranscriptProgressed,
            HandshakeMessageType: QuicTlsHandshakeMessageType.ClientHello,
            HandshakeMessageLength: 1,
            SelectedCipherSuite: QuicTlsCipherSuite.TlsAes128GcmSha256,
            TranscriptHashAlgorithm: QuicTlsTranscriptHashAlgorithm.Sha256,
            TransportParameters: peerTransportParameters,
            TranscriptPhase: QuicTlsTranscriptPhase.Completed)));
        Assert.True(runtime.TlsState.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.TranscriptProgressed,
            HandshakeMessageType: QuicTlsHandshakeMessageType.Finished,
            HandshakeMessageLength: 1,
            TranscriptPhase: QuicTlsTranscriptPhase.Completed)));
        Assert.True(runtime.TlsState.TryMarkPeerFinishedVerified());
        Assert.True(runtime.TlsState.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.OneRttProtectPacketProtectionMaterialAvailable,
            PacketProtectionMaterial: QuicS9P3TokenEmissionTestSupport.CreateOneRttMaterial())));
        Assert.True(runtime.TlsState.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeysAvailable,
            EncryptionLevel: QuicTlsEncryptionLevel.OneRtt)));

        return runtime;
    }

    internal static QuicConnectionTransitionResult CompletePeerHandshakeTranscript(
        QuicConnectionRuntime runtime,
        long observedAtTicks)
    {
        return runtime.Transition(
            new QuicConnectionPeerHandshakeTranscriptCompletedEvent(ObservedAtTicks: observedAtTicks),
            nowTicks: observedAtTicks);
    }

    internal static byte[] CreateProtectedApplicationDataPacket(
        QuicConnectionRuntime runtime,
        ReadOnlySpan<byte> payload)
    {
        Assert.True(runtime.TlsState.OneRttOpenPacketProtectionMaterial.HasValue);
        byte[] destinationConnectionId = runtime.CurrentPeerDestinationConnectionId.ToArray();
        QuicHandshakeFlowCoordinator coordinator = new(destinationConnectionId);
        Assert.True(coordinator.TrySetDestinationConnectionId(destinationConnectionId));
        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            payload,
            runtime.TlsState.OneRttOpenPacketProtectionMaterial.Value,
            runtime.TlsState.CurrentOneRttKeyPhase == 1,
            out byte[] protectedPacket));

        return protectedPacket;
    }

    internal static bool IsHandshakeDonePlaintext(QuicConnectionSentPacket sentPacket)
    {
        return sentPacket.PlaintextPayload.Span.SequenceEqual(QuicFrameTestData.BuildHandshakeDoneFrame());
    }

    private static byte[] CreateScalar(byte value)
    {
        byte[] scalar = new byte[32];
        scalar[^1] = value;
        return scalar;
    }
}
