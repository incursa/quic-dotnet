using System.Diagnostics;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S12P5-0006")]
public sealed class REQ_QUIC_RFC9000_S12P5_0006
{
    private static readonly byte[] InitialDestinationConnectionId =
    [
        0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08,
    ];

    private static readonly QuicConnectionPathIdentity BootstrapPath =
        new("203.0.113.10", "198.51.100.20", 443, 12345);

    private static readonly QuicTransportParameters PeerTransportParameters = new()
    {
        InitialSourceConnectionId = [0x10, 0x11, 0x12],
    };

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerHandshakeDonePacketLossQueuesRepairUntilAcknowledged()
    {
        QuicConnectionRuntime runtime = CreateRuntime(QuicTlsRole.Server);
        PrepareHandshakeDoneSendState(runtime);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPeerHandshakeTranscriptCompletedEvent(ObservedAtTicks: 1),
            nowTicks: 1);

        Assert.True(result.StateChanged);
        Assert.Contains(result.Effects, effect => effect is QuicConnectionSendDatagramEffect);

        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> trackedPacket = Assert.Single(
            runtime.SendRuntime.SentPackets);

        Assert.Equal(QuicPacketNumberSpace.ApplicationData, trackedPacket.Key.PacketNumberSpace);
        Assert.Equal(0UL, trackedPacket.Key.PacketNumber);
        Assert.True(trackedPacket.Value.AckEliciting);
        Assert.True(trackedPacket.Value.Retransmittable);

        Assert.True(runtime.SendRuntime.TryRegisterLoss(
            trackedPacket.Key.PacketNumberSpace,
            trackedPacket.Key.PacketNumber,
            handshakeConfirmed: true));

        Assert.Equal(1, runtime.SendRuntime.PendingRetransmissionCount);
        Assert.True(runtime.SendRuntime.TryAcknowledgePacket(
            trackedPacket.Key.PacketNumberSpace,
            trackedPacket.Key.PacketNumber,
            handshakeConfirmed: true));
        Assert.Equal(0, runtime.SendRuntime.PendingRetransmissionCount);
        Assert.False(runtime.SendRuntime.TryDequeueRetransmission(out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClientHandshakeDoneTransitionDoesNotEmitAHandshakeDonePacket()
    {
        QuicConnectionRuntime runtime = CreateRuntime(QuicTlsRole.Client);
        PrepareHandshakeDoneSendState(runtime);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPeerHandshakeTranscriptCompletedEvent(ObservedAtTicks: 1),
            nowTicks: 1);

        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionSendDatagramEffect);
        Assert.Empty(runtime.SendRuntime.SentPackets);
        Assert.Equal(0, runtime.SendRuntime.PendingRetransmissionCount);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryBuildOutboundHandshakeDonePayload_WritesOnlyTheHandshakeDoneTypeByte()
    {
        QuicConnectionRuntime runtime = CreateRuntime(QuicTlsRole.Server);

        Assert.True(runtime.TryBuildOutboundHandshakeDonePayload(out byte[] payload));
        Assert.Single(payload);
        Assert.Equal(0x1E, payload[0]);

        Assert.True(QuicFrameCodec.TryParseHandshakeDoneFrame(payload, out _, out int bytesConsumed));
        Assert.Equal(1, bytesConsumed);
    }

    private static QuicConnectionRuntime CreateRuntime(QuicTlsRole tlsRole)
    {
        QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            new FakeMonotonicClock(0),
            tlsRole: tlsRole,
            localHandshakePrivateKey: CreateScalar(0x11));

        Assert.True(runtime.TrySetHandshakeDestinationConnectionId(InitialDestinationConnectionId));
        return runtime;
    }

    private static void PrepareHandshakeDoneSendState(QuicConnectionRuntime runtime)
    {
        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 0,
                BootstrapPath,
                new byte[1200]),
            nowTicks: 0).StateChanged);

        Assert.True(runtime.TlsState.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.TranscriptProgressed,
            HandshakeMessageType: QuicTlsHandshakeMessageType.ClientHello,
            HandshakeMessageLength: 1,
            SelectedCipherSuite: QuicTlsCipherSuite.TlsAes128GcmSha256,
            TranscriptHashAlgorithm: QuicTlsTranscriptHashAlgorithm.Sha256,
            TransportParameters: PeerTransportParameters,
            TranscriptPhase: QuicTlsTranscriptPhase.Completed)));

        Assert.True(runtime.TlsState.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.TranscriptProgressed,
            HandshakeMessageType: QuicTlsHandshakeMessageType.Finished,
            HandshakeMessageLength: 1,
            TranscriptPhase: QuicTlsTranscriptPhase.Completed)));

        Assert.True(runtime.TlsState.TryMarkPeerFinishedVerified());

        Assert.True(runtime.TlsState.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.OneRttProtectPacketProtectionMaterialAvailable,
            PacketProtectionMaterial: CreateOneRttMaterial())));
    }

    private static QuicTlsPacketProtectionMaterial CreateOneRttMaterial()
    {
        Assert.True(QuicTlsPacketProtectionMaterial.TryCreate(
            QuicTlsEncryptionLevel.OneRtt,
            QuicAeadAlgorithm.Aes128Gcm,
            CreateSequentialBytes(0x11, 16),
            CreateSequentialBytes(0x21, 12),
            CreateSequentialBytes(0x31, 16),
            new QuicAeadUsageLimits(64, 128),
            out QuicTlsPacketProtectionMaterial material));

        return material;
    }

    private static byte[] CreateSequentialBytes(byte startValue, int length)
    {
        byte[] bytes = new byte[length];
        for (int index = 0; index < bytes.Length; index++)
        {
            bytes[index] = unchecked((byte)(startValue + index));
        }

        return bytes;
    }

    private static byte[] CreateScalar(byte value)
    {
        byte[] scalar = new byte[32];
        scalar[^1] = value;
        return scalar;
    }
}
