namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P2P1-0007">When a PTO timer expires, the PTO backoff MUST be increased, which doubles the PTO period.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S6P2P1-0007")]
public sealed class REQ_QUIC_RFC9002_S6P2P1_0007
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TrySelectLossDetectionTimer_DoublesThePtoAfterAProbeTimeoutExpires()
    {
        QuicSenderRecoveryRuntime runtime = new(initialRttMicros: 2_500);
        runtime.RecordPacketSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 7,
            sentBytes: 1_200,
            sentAtMicros: 0,
            ackEliciting: true);

        Assert.True(runtime.TrySelectLossDetectionTimer(
            nowMicros: 0,
            maxAckDelayMicros: 0,
            handshakeConfirmed: true,
            serverAtAntiAmplificationLimit: false,
            peerAddressValidationComplete: true,
            handshakeKeysAvailable: true,
            out ulong selectedRecoveryTimerMicros,
            out QuicPacketNumberSpace selectedPacketNumberSpace));

        Assert.Equal(QuicPacketNumberSpace.ApplicationData, selectedPacketNumberSpace);
        Assert.Equal(7_500UL, selectedRecoveryTimerMicros);

        runtime.RecordProbeTimeoutExpired();

        Assert.Equal(1, runtime.ProbeTimeoutBackoffCount);
        Assert.True(runtime.TrySelectLossDetectionTimer(
            nowMicros: 0,
            maxAckDelayMicros: 0,
            handshakeConfirmed: true,
            serverAtAntiAmplificationLimit: false,
            peerAddressValidationComplete: true,
            handshakeKeysAvailable: true,
            out selectedRecoveryTimerMicros,
            out selectedPacketNumberSpace));

        Assert.Equal(QuicPacketNumberSpace.ApplicationData, selectedPacketNumberSpace);
        Assert.Equal(15_000UL, selectedRecoveryTimerMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TrySelectLossDetectionTimer_LeavesTheBasePtoInPlaceBeforeAnyProbeTimeoutExpires()
    {
        QuicSenderRecoveryRuntime runtime = new(initialRttMicros: 2_500);
        runtime.RecordPacketSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 7,
            sentBytes: 1_200,
            sentAtMicros: 0,
            ackEliciting: true);

        Assert.True(runtime.TrySelectLossDetectionTimer(
            nowMicros: 0,
            maxAckDelayMicros: 0,
            handshakeConfirmed: true,
            serverAtAntiAmplificationLimit: false,
            peerAddressValidationComplete: true,
            handshakeKeysAvailable: true,
            out ulong selectedRecoveryTimerMicros,
            out QuicPacketNumberSpace selectedPacketNumberSpace));

        Assert.Equal(0, runtime.ProbeTimeoutBackoffCount);
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, selectedPacketNumberSpace);
        Assert.Equal(7_500UL, selectedRecoveryTimerMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TrySelectLossDetectionTimer_ContinuesDoublingAfterRepeatedProbeTimeoutExpirations()
    {
        QuicSenderRecoveryRuntime runtime = new(initialRttMicros: 2_500);
        runtime.RecordPacketSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 7,
            sentBytes: 1_200,
            sentAtMicros: 0,
            ackEliciting: true);

        runtime.RecordProbeTimeoutExpired();
        runtime.RecordProbeTimeoutExpired();

        Assert.Equal(2, runtime.ProbeTimeoutBackoffCount);
        Assert.True(runtime.TrySelectLossDetectionTimer(
            nowMicros: 0,
            maxAckDelayMicros: 0,
            handshakeConfirmed: true,
            serverAtAntiAmplificationLimit: false,
            peerAddressValidationComplete: true,
            handshakeKeysAvailable: true,
            out ulong selectedRecoveryTimerMicros,
            out QuicPacketNumberSpace selectedPacketNumberSpace));

        Assert.Equal(QuicPacketNumberSpace.ApplicationData, selectedPacketNumberSpace);
        Assert.Equal(30_000UL, selectedRecoveryTimerMicros);
    }
}
