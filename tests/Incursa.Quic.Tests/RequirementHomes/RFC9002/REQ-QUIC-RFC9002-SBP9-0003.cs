namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-SBP9-0003">When Initial or Handshake keys are discarded, the sender MUST reset `time_of_last_ack_eliciting_packet[pn_space]`, `loss_time[pn_space]`, and `pto_count`, and set the loss detection timer.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-SBP9-0003")]
public sealed class REQ_QUIC_RFC9002_SBP9_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TrySelectLossDetectionTimerMicros_PrefersTheResetLossDeadlineOverPto()
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
    public void TrySelectLossDetectionTimerMicros_CancelsPtoWhenRecoveryIsBlocked(
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
    public void TrySelectLossDetectionTimerMicros_UsesAnImmediateDeadlineWhenTheResetTimerIsZero()
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
}
