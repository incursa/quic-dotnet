namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-SBP9-0001">When Initial or Handshake keys are discarded, packets in that space MUST no longer count toward bytes_in_flight.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-SBP9-0001")]
public sealed class REQ_QUIC_RFC9002_SBP9_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryDetectPersistentCongestion_RemovesInitialPacketsFromBytesInFlightWhenKeysAreDiscarded()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);

        Assert.True(state.TryDetectPersistentCongestion(
            [
                new(QuicPacketNumberSpace.Initial, 500, 1_200, ackEliciting: true, inFlight: true, acknowledged: false, lost: true),
            ],
            firstRttSampleMicros: 1_000,
            smoothedRttMicros: 1_000,
            rttVarMicros: 0,
            maxAckDelayMicros: 0,
            out bool persistentCongestionDetected));

        Assert.False(persistentCongestionDetected);
        Assert.Equal(10_800UL, state.BytesInFlightBytes);
        Assert.False(state.HasRecoveryStartTime);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryDetectPersistentCongestion_DoesNotRemoveInitialPacketsThatWereNotInFlight()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);

        Assert.True(state.TryDetectPersistentCongestion(
            [
                new(QuicPacketNumberSpace.Initial, 500, 1_200, ackEliciting: true, inFlight: false, acknowledged: false, lost: true),
            ],
            firstRttSampleMicros: 1_000,
            smoothedRttMicros: 1_000,
            rttVarMicros: 0,
            maxAckDelayMicros: 0,
            out bool persistentCongestionDetected));

        Assert.False(persistentCongestionDetected);
        Assert.Equal(12_000UL, state.BytesInFlightBytes);
        Assert.False(state.HasRecoveryStartTime);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryDetectPersistentCongestion_RemovesHandshakePacketsAtTheFirstRttSampleBoundary()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);

        Assert.True(state.TryDetectPersistentCongestion(
            [
                new(QuicPacketNumberSpace.Handshake, 1_000, 1_200, ackEliciting: true, inFlight: true, acknowledged: false, lost: true),
            ],
            firstRttSampleMicros: 1_000,
            smoothedRttMicros: 1_000,
            rttVarMicros: 0,
            maxAckDelayMicros: 0,
            out bool persistentCongestionDetected));

        Assert.False(persistentCongestionDetected);
        Assert.Equal(10_800UL, state.BytesInFlightBytes);
        Assert.False(state.HasRecoveryStartTime);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryDiscardPacketNumberSpace_RemovesRuntimeInitialBytesInFlightWhenKeysAreDiscarded()
    {
        QuicConnectionSendRuntime runtime = new();
        TrackSentPacket(runtime, QuicPacketNumberSpace.Initial, packetNumber: 1, payloadBytes: 1_200);
        TrackSentPacket(runtime, QuicPacketNumberSpace.Handshake, packetNumber: 2, payloadBytes: 1_200);
        TrackSentPacket(runtime, QuicPacketNumberSpace.ApplicationData, packetNumber: 3, payloadBytes: 1_200);

        Assert.Equal(3_600UL, runtime.FlowController.CongestionControlState.BytesInFlightBytes);

        Assert.True(runtime.TryDiscardPacketNumberSpace(QuicPacketNumberSpace.Initial));

        Assert.Equal(2_400UL, runtime.FlowController.CongestionControlState.BytesInFlightBytes);
        Assert.DoesNotContain(runtime.SentPackets.Keys, key => key.PacketNumberSpace == QuicPacketNumberSpace.Initial);
        Assert.Contains(runtime.SentPackets.Keys, key => key.PacketNumberSpace == QuicPacketNumberSpace.Handshake);
        Assert.Contains(runtime.SentPackets.Keys, key => key.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData);
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
