using System.Diagnostics;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P3-0032">PING and PADDING frames contain no information, so lost PING or PADDING frames MUST NOT require repair.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P3-0032")]
public sealed class REQ_QUIC_RFC9000_S13P3_0032
{
    private static readonly byte[] InitialDestinationConnectionId =
    [
        0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08,
    ];

    private static readonly byte[] InitialSourceConnectionId =
    [
        0x21, 0x22, 0x23, 0x24,
    ];

    private static readonly QuicConnectionPathIdentity BootstrapPath =
        new("203.0.113.10", "198.51.100.20", 443, 12345);

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ZeroRttPingBootstrapPacketIsTrackedAsAProbeAndNeverQueuedForRepair()
    {
        QuicDetachedResumptionTicketSnapshot detachedResumptionTicketSnapshot =
            QuicResumptionClientHelloTestSupport.CreateDetachedResumptionTicketSnapshot(ticketMaxEarlyDataSize: 4096);
        QuicTransportParameters localTransportParameters =
            QuicLoopbackEstablishmentTestSupport.CreateSupportedTransportParameters(InitialSourceConnectionId);
        byte[] localHandshakePrivateKey = CreateScalar(0x11);
        long nowTicks = detachedResumptionTicketSnapshot.CapturedAtTicks + Stopwatch.Frequency;

        using QuicConnectionRuntime clientRuntime = CreateClientRuntime(
            localHandshakePrivateKey,
            detachedResumptionTicketSnapshot);

        Assert.True(clientRuntime.HasDormantDetachedResumptionTicketSnapshot);
        Assert.True(clientRuntime.HasDormantEarlyDataAttemptReadiness);

        QuicConnectionTransitionResult result = clientRuntime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: nowTicks,
                LocalTransportParameters: localTransportParameters),
            nowTicks);

        Assert.True(result.StateChanged);

        QuicConnectionSendDatagramEffect zeroRttSend = Assert.Single(GetZeroRttSendEffects(result.Effects));
        Assert.True(IsZeroRttPacket(zeroRttSend.Datagram.Span));

        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> trackedPacket = Assert.Single(
            clientRuntime.SendRuntime.SentPackets,
            entry => entry.Key.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData);

        Assert.Equal(0UL, trackedPacket.Key.PacketNumber);
        Assert.True(trackedPacket.Value.ProbePacket);
        Assert.False(trackedPacket.Value.Retransmittable);
        Assert.Equal((ulong)zeroRttSend.Datagram.Length, trackedPacket.Value.PayloadBytes);

        Assert.True(clientRuntime.SendRuntime.TryRegisterLoss(
            trackedPacket.Key.PacketNumberSpace,
            trackedPacket.Key.PacketNumber,
            handshakeConfirmed: false));
        Assert.Equal(0, clientRuntime.SendRuntime.PendingRetransmissionCount);
        Assert.False(clientRuntime.SendRuntime.TryDequeueRetransmission(out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void LossOfAPaddingOnlyPacketDoesNotQueueRepair()
    {
        QuicConnectionSendRuntime runtime = new();
        byte[] paddingPacket = QuicFrameTestData.BuildPaddingFrame();

        Assert.True(QuicFrameCodec.TryParsePaddingFrame(paddingPacket, out int bytesConsumed));
        Assert.Equal(paddingPacket.Length, bytesConsumed);

        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 7,
            PayloadBytes: (ulong)paddingPacket.Length,
            SentAtMicros: 100,
            AckEliciting: false,
            Retransmittable: false,
            PacketBytes: paddingPacket));

        Assert.True(runtime.TryRegisterLoss(
            QuicPacketNumberSpace.ApplicationData,
            7,
            handshakeConfirmed: false));

        Assert.Equal(0, runtime.PendingRetransmissionCount);
        Assert.False(runtime.TryDequeueRetransmission(out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RetransmittablePacketLossQueuesRepair()
    {
        QuicConnectionSendRuntime runtime = new();
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 7,
            PayloadBytes: 1_200,
            SentAtMicros: 100,
            AckEliciting: true));

        Assert.True(runtime.TryRegisterLoss(
            QuicPacketNumberSpace.ApplicationData,
            7,
            handshakeConfirmed: false));

        Assert.Equal(1, runtime.PendingRetransmissionCount);
        Assert.True(runtime.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan retransmission));
        Assert.Equal(7UL, retransmission.PacketNumber);
        Assert.Equal(1_200UL, retransmission.PayloadBytes);
        Assert.False(runtime.TryDequeueRetransmission(out _));
    }

    private static QuicConnectionRuntime CreateClientRuntime(
        byte[] localHandshakePrivateKey,
        QuicDetachedResumptionTicketSnapshot? detachedResumptionTicketSnapshot = null)
    {
        QuicConnectionRuntime clientRuntime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            new FakeMonotonicClock(0),
            tlsRole: QuicTlsRole.Client,
            localHandshakePrivateKey: localHandshakePrivateKey,
            detachedResumptionTicketSnapshot: detachedResumptionTicketSnapshot);

        Assert.True(clientRuntime.TryConfigureInitialPacketProtection(InitialDestinationConnectionId));
        Assert.True(clientRuntime.TrySetBootstrapOutboundPath(BootstrapPath));
        Assert.True(clientRuntime.TrySetHandshakeSourceConnectionId(InitialSourceConnectionId));
        return clientRuntime;
    }

    private static QuicConnectionSendDatagramEffect[] GetZeroRttSendEffects(IEnumerable<QuicConnectionEffect> effects)
    {
        List<QuicConnectionSendDatagramEffect> zeroRttEffects = [];

        foreach (QuicConnectionSendDatagramEffect sendEffect in effects.OfType<QuicConnectionSendDatagramEffect>())
        {
            if (IsZeroRttPacket(sendEffect.Datagram.Span))
            {
                zeroRttEffects.Add(sendEffect);
            }
        }

        return zeroRttEffects.ToArray();
    }

    private static bool IsZeroRttPacket(ReadOnlySpan<byte> packet)
    {
        return QuicPacketParser.TryParseLongHeader(
            packet,
            out QuicLongHeaderPacket longHeader)
            && longHeader.Version == 1
            && longHeader.LongPacketTypeBits == QuicLongPacketTypeBits.ZeroRtt;
    }

    private static byte[] CreateScalar(byte value)
    {
        byte[] scalar = new byte[32];
        scalar[^1] = value;
        return scalar;
    }
}
