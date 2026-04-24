namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-SAP8-0006">`SetLossDetectionTimer` MUST update the timer to the earliest pending loss time when one exists, cancel the timer when the server is at the anti-amplification limit or when no ack-eliciting packets are in flight and peer address validation is complete, and otherwise update the timer to the PTO timeout.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-SAP8-0006")]
public sealed class REQ_QUIC_RFC9002_SAP8_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TrySelectLossDetectionTimerMicros_ChoosesTheEarliestPendingLossTime()
    {
        Assert.True(QuicRecoveryTiming.TrySelectLossDetectionTimerMicros(
            earliestPendingLossTimeMicros: 1_500,
            probeTimeoutMicros: 2_800,
            serverAtAntiAmplificationLimit: false,
            noAckElicitingPacketsInFlight: false,
            peerAddressValidationComplete: false,
            out ulong selectedTimerMicros));

        Assert.Equal(1_500UL, selectedTimerMicros);
    }

    [Theory]
    [InlineData(true, false, false)]
    [InlineData(false, true, true)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TrySelectLossDetectionTimerMicros_CancelsTheTimerWhenRecoveryIsBlocked(
        bool serverAtAntiAmplificationLimit,
        bool noAckElicitingPacketsInFlight,
        bool peerAddressValidationComplete)
    {
        Assert.False(QuicRecoveryTiming.TrySelectLossDetectionTimerMicros(
            earliestPendingLossTimeMicros: null,
            probeTimeoutMicros: 2_800,
            serverAtAntiAmplificationLimit: serverAtAntiAmplificationLimit,
            noAckElicitingPacketsInFlight: noAckElicitingPacketsInFlight,
            peerAddressValidationComplete: peerAddressValidationComplete,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TrySelectLossDetectionTimerMicros_UsesThePtoTimeoutWhenNoLossTimeIsPending()
    {
        Assert.True(QuicRecoveryTiming.TrySelectLossDetectionTimerMicros(
            earliestPendingLossTimeMicros: null,
            probeTimeoutMicros: 0,
            serverAtAntiAmplificationLimit: false,
            noAckElicitingPacketsInFlight: false,
            peerAddressValidationComplete: false,
            out ulong selectedTimerMicros));

        Assert.Equal(0UL, selectedTimerMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TrySelectLossDetectionTimer_PeeksAnImmediateLossWithoutDiscardingIt()
    {
        QuicRecoveryController controller = new();
        controller.RecordPacketSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 1,
            sentAtMicros: 0,
            isAckElicitingPacket: true,
            packetProtectionLevel: QuicTlsEncryptionLevel.OneRtt);
        controller.RecordPacketSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 4,
            sentAtMicros: 0,
            isAckElicitingPacket: true,
            packetProtectionLevel: QuicTlsEncryptionLevel.OneRtt);
        Assert.True(controller.RecordAcknowledgment(
            QuicPacketNumberSpace.ApplicationData,
            largestAcknowledgedPacketNumber: 4,
            ackReceivedAtMicros: 100,
            newlyAcknowledgedAckElicitingPacketNumbers: [4],
            ackDelayMicros: 0,
            handshakeConfirmed: true,
            peerMaxAckDelayMicros: 0));

        Assert.True(controller.TrySelectLossDetectionTimer(
            nowMicros: 100,
            maxAckDelayMicros: 0,
            handshakeConfirmed: true,
            serverAtAntiAmplificationLimit: false,
            peerAddressValidationComplete: true,
            handshakeKeysAvailable: true,
            out ulong selectedRecoveryTimerMicros,
            out QuicPacketNumberSpace selectedPacketNumberSpace));
        Assert.Equal(100UL, selectedRecoveryTimerMicros);
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, selectedPacketNumberSpace);

        IReadOnlyList<QuicLostPacket> lostPackets = controller.DetectLostPackets(
            nowMicros: 100,
            out _,
            out _);
        QuicLostPacket lostPacket = Assert.Single(lostPackets);
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, lostPacket.PacketNumberSpace);
        Assert.Equal(1UL, lostPacket.PacketNumber);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void TrySelectLossDetectionTimerMicros_FuzzesLossCancelAndPtoPriority()
    {
        for (uint sampleIndex = 0; sampleIndex < 192; sampleIndex++)
        {
            ulong? pendingLossTimeMicros = sampleIndex % 5 == 0 ? 1_000 + sampleIndex : null;
            ulong? probeTimeoutMicros = sampleIndex % 7 == 0 ? null : 5_000 + sampleIndex;
            bool serverAtAntiAmplificationLimit = (sampleIndex & 0x1) != 0;
            bool noAckElicitingPacketsInFlight = (sampleIndex & 0x2) != 0;
            bool peerAddressValidationComplete = (sampleIndex & 0x4) != 0;

            bool selected = QuicRecoveryTiming.TrySelectLossDetectionTimerMicros(
                pendingLossTimeMicros,
                probeTimeoutMicros,
                serverAtAntiAmplificationLimit,
                noAckElicitingPacketsInFlight,
                peerAddressValidationComplete,
                out ulong selectedTimerMicros);

            if (pendingLossTimeMicros.HasValue)
            {
                Assert.True(selected);
                Assert.Equal(pendingLossTimeMicros.Value, selectedTimerMicros);
                continue;
            }

            if (serverAtAntiAmplificationLimit || (noAckElicitingPacketsInFlight && peerAddressValidationComplete))
            {
                Assert.False(selected);
                continue;
            }

            if (probeTimeoutMicros.HasValue)
            {
                Assert.True(selected);
                Assert.Equal(probeTimeoutMicros.Value, selectedTimerMicros);
            }
            else
            {
                Assert.False(selected);
            }
        }
    }
}
