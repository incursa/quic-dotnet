namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-SBP9-0002">When Initial or Handshake keys are discarded, the sender MUST remove the discarded packets from `bytes_in_flight` and clear `sent_packets` for that packet number space.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-SBP9-0002")]
public sealed class REQ_QUIC_RFC9002_SBP9_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryDetectPersistentCongestion_RemovesInitialAndHandshakePacketsFromCongestionAccounting()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);

        Assert.True(state.TryDetectPersistentCongestion(
            [
                new(QuicPacketNumberSpace.Initial, 2_000, 1_200, ackEliciting: true, inFlight: true, acknowledged: false, lost: true),
                new(QuicPacketNumberSpace.Handshake, 9_000, 1_200, ackEliciting: true, inFlight: true, acknowledged: false, lost: true),
            ],
            firstRttSampleMicros: 1_000,
            smoothedRttMicros: 1_000,
            rttVarMicros: 0,
            maxAckDelayMicros: 0,
            out bool persistentCongestionDetected,
            applyReset: false));

        Assert.True(persistentCongestionDetected);
        Assert.Equal(9_600UL, state.BytesInFlightBytes);
        Assert.Equal(9_000UL, state.RecoveryStartTimeMicros);
        Assert.Equal(6_000UL, state.CongestionWindowBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryDetectPersistentCongestion_DoesNotChangeCongestionAccountingForPacketsThatWereNotInFlight()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);

        Assert.True(state.TryDetectPersistentCongestion(
            [
                new(QuicPacketNumberSpace.Initial, 500, 1_200, ackEliciting: true, inFlight: false, acknowledged: false, lost: true),
                new(QuicPacketNumberSpace.Handshake, 700, 1_200, ackEliciting: true, inFlight: false, acknowledged: false, lost: true),
            ],
            firstRttSampleMicros: 1_000,
            smoothedRttMicros: 1_000,
            rttVarMicros: 0,
            maxAckDelayMicros: 0,
            out bool persistentCongestionDetected,
            applyReset: false));

        Assert.False(persistentCongestionDetected);
        Assert.Equal(12_000UL, state.BytesInFlightBytes);
        Assert.False(state.HasRecoveryStartTime);
        Assert.Equal(12_000UL, state.CongestionWindowBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryDetectPersistentCongestion_RemovesPacketsAtThePersistentCongestionDurationBoundary()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);

        Assert.True(state.TryDetectPersistentCongestion(
            [
                new(QuicPacketNumberSpace.Initial, 2_000, 1_200, ackEliciting: true, inFlight: true, acknowledged: false, lost: true),
                new(QuicPacketNumberSpace.Handshake, 8_000, 1_200, ackEliciting: true, inFlight: true, acknowledged: false, lost: true),
            ],
            firstRttSampleMicros: 1_000,
            smoothedRttMicros: 1_000,
            rttVarMicros: 0,
            maxAckDelayMicros: 0,
            out bool persistentCongestionDetected,
            applyReset: false));

        Assert.True(persistentCongestionDetected);
        Assert.Equal(9_600UL, state.BytesInFlightBytes);
        Assert.Equal(8_000UL, state.RecoveryStartTimeMicros);
        Assert.Equal(6_000UL, state.CongestionWindowBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryDiscardPacketNumberSpace_ClearsRuntimeSentPacketsAndPendingRetransmissionsForDiscardedSpaces()
    {
        QuicConnectionSendRuntime runtime = new();
        TrackSentPacket(runtime, QuicPacketNumberSpace.Initial, packetNumber: 1, payloadBytes: 1_200);
        TrackSentPacket(runtime, QuicPacketNumberSpace.Initial, packetNumber: 2, payloadBytes: 1_200);
        TrackSentPacket(runtime, QuicPacketNumberSpace.Handshake, packetNumber: 3, payloadBytes: 1_200);
        TrackSentPacket(runtime, QuicPacketNumberSpace.Handshake, packetNumber: 4, payloadBytes: 1_200);
        TrackSentPacket(runtime, QuicPacketNumberSpace.ApplicationData, packetNumber: 5, payloadBytes: 1_200);

        Assert.True(runtime.TryRegisterLoss(QuicPacketNumberSpace.Initial, packetNumber: 2));
        Assert.True(runtime.TryRegisterLoss(QuicPacketNumberSpace.Handshake, packetNumber: 4, handshakeConfirmed: true));
        Assert.Equal(2, runtime.PendingRetransmissionCount);

        Assert.True(runtime.TryDiscardPacketNumberSpace(QuicPacketNumberSpace.Initial));
        Assert.DoesNotContain(runtime.SentPackets.Keys, key => key.PacketNumberSpace == QuicPacketNumberSpace.Initial);
        Assert.Equal(1, runtime.PendingRetransmissionCount);

        Assert.True(runtime.TryDiscardPacketNumberSpace(QuicPacketNumberSpace.Handshake));
        Assert.DoesNotContain(runtime.SentPackets.Keys, key => key.PacketNumberSpace == QuicPacketNumberSpace.Handshake);
        Assert.Equal(0, runtime.PendingRetransmissionCount);
        Assert.Single(runtime.SentPackets);
        Assert.Equal(1_200UL, runtime.FlowController.CongestionControlState.BytesInFlightBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryDiscardPacketNumberSpace_DoesNotClearApplicationDataRuntimeState()
    {
        QuicConnectionSendRuntime runtime = new();
        TrackSentPacket(runtime, QuicPacketNumberSpace.ApplicationData, packetNumber: 9, payloadBytes: 1_200);

        Assert.True(runtime.TryDiscardPacketNumberSpace(QuicPacketNumberSpace.Initial));

        Assert.Single(runtime.SentPackets);
        Assert.Contains(runtime.SentPackets.Keys, key => key.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData);
        Assert.Equal(1_200UL, runtime.FlowController.CongestionControlState.BytesInFlightBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void FuzzDiscardingEarlyPacketNumberSpacesClearsOnlyDiscardedRuntimeLedger()
    {
        Random random = new(0x5B9002);

        for (int iteration = 0; iteration < 64; iteration++)
        {
            QuicConnectionSendRuntime runtime = new();
            ulong expectedApplicationBytesInFlight = 0;
            int expectedPendingRetransmissions = 0;

            TrackRandomSpace(runtime, random, QuicPacketNumberSpace.Initial, 10);
            TrackRandomSpace(runtime, random, QuicPacketNumberSpace.Handshake, 20);
            List<(ulong PacketNumber, ulong PayloadBytes)> applicationPackets =
                TrackRandomSpace(runtime, random, QuicPacketNumberSpace.ApplicationData, 30);

            foreach ((_, ulong payloadBytes) in applicationPackets)
            {
                expectedApplicationBytesInFlight += payloadBytes;
            }

            Assert.True(runtime.TryRegisterLoss(QuicPacketNumberSpace.Initial, packetNumber: 10));
            Assert.True(runtime.TryRegisterLoss(QuicPacketNumberSpace.Handshake, packetNumber: 20, handshakeConfirmed: true));
            if (random.Next(2) == 0)
            {
                (ulong packetNumber, ulong payloadBytes) = applicationPackets[0];
                Assert.True(runtime.TryRegisterLoss(QuicPacketNumberSpace.ApplicationData, packetNumber, handshakeConfirmed: true));
                expectedApplicationBytesInFlight -= payloadBytes;
                expectedPendingRetransmissions++;
            }

            Assert.True(runtime.TryDiscardPacketNumberSpace(QuicPacketNumberSpace.Initial));
            Assert.True(runtime.TryDiscardPacketNumberSpace(QuicPacketNumberSpace.Handshake));

            Assert.DoesNotContain(runtime.SentPackets.Keys, key => key.PacketNumberSpace == QuicPacketNumberSpace.Initial);
            Assert.DoesNotContain(runtime.SentPackets.Keys, key => key.PacketNumberSpace == QuicPacketNumberSpace.Handshake);
            Assert.All(runtime.SentPackets.Keys, key => Assert.Equal(QuicPacketNumberSpace.ApplicationData, key.PacketNumberSpace));
            Assert.Equal(expectedApplicationBytesInFlight, runtime.FlowController.CongestionControlState.BytesInFlightBytes);
            Assert.Equal(expectedPendingRetransmissions, runtime.PendingRetransmissionCount);
        }
    }

    private static List<(ulong PacketNumber, ulong PayloadBytes)> TrackRandomSpace(
        QuicConnectionSendRuntime runtime,
        Random random,
        QuicPacketNumberSpace packetNumberSpace,
        ulong firstPacketNumber)
    {
        int packetCount = random.Next(1, 5);
        List<(ulong PacketNumber, ulong PayloadBytes)> packets = [];
        for (int index = 0; index < packetCount; index++)
        {
            ulong packetNumber = firstPacketNumber + (ulong)index;
            ulong payloadBytes = (ulong)random.Next(512, 2_401);
            TrackSentPacket(runtime, packetNumberSpace, packetNumber, payloadBytes);
            packets.Add((packetNumber, payloadBytes));
        }

        return packets;
    }

    private static void TrackSentPacket(
        QuicConnectionSendRuntime runtime,
        QuicPacketNumberSpace packetNumberSpace,
        ulong packetNumber,
        ulong payloadBytes)
    {
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            packetNumberSpace,
            packetNumber,
            payloadBytes,
            SentAtMicros: packetNumber,
            PacketProtectionLevel: packetNumberSpace switch
            {
                QuicPacketNumberSpace.Initial => QuicTlsEncryptionLevel.Initial,
                QuicPacketNumberSpace.Handshake => QuicTlsEncryptionLevel.Handshake,
                _ => QuicTlsEncryptionLevel.OneRtt,
            }));
    }
}
