namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-SAP6-0002">If the loss detection timer would already have expired while the anti-amplification limit was applied, the endpoint MUST process the timeout immediately.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-SAP6-0002")]
public sealed class REQ_QUIC_RFC9002_SAP6_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TrySelectLossDetectionTimerMicros_ExecutesAnAlreadyExpiredTimerAsSoonAsAmplificationBlockingEnds()
    {
        QuicAntiAmplificationBudget budget = CreateBlockedBudget();

        Assert.False(QuicRecoveryTiming.TrySelectLossDetectionTimerMicros(
            earliestPendingLossTimeMicros: null,
            probeTimeoutMicros: 0,
            serverAtAntiAmplificationLimit: budget.RemainingSendBudget == 0,
            noAckElicitingPacketsInFlight: false,
            peerAddressValidationComplete: false,
            out _));

        Assert.True(budget.TryRegisterReceivedDatagramPayloadBytes(1, uniquelyAttributedToSingleConnection: true));

        Assert.True(QuicRecoveryTiming.TrySelectLossDetectionTimerMicros(
            earliestPendingLossTimeMicros: null,
            probeTimeoutMicros: 0,
            serverAtAntiAmplificationLimit: budget.RemainingSendBudget == 0,
            noAckElicitingPacketsInFlight: false,
            peerAddressValidationComplete: false,
            out ulong selectedTimerMicros));

        Assert.Equal(0UL, selectedTimerMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TrySelectLossDetectionTimerMicros_DoesNotExecuteAnExpiredTimerWhenDatagramReceiptDoesNotRestoreBudget()
    {
        QuicAntiAmplificationBudget budget = CreateBlockedBudget();

        Assert.True(budget.TryRegisterReceivedDatagramPayloadBytes(1, uniquelyAttributedToSingleConnection: false));
        Assert.Equal(0UL, budget.RemainingSendBudget);

        Assert.False(QuicRecoveryTiming.TrySelectLossDetectionTimerMicros(
            earliestPendingLossTimeMicros: null,
            probeTimeoutMicros: 0,
            serverAtAntiAmplificationLimit: budget.RemainingSendBudget == 0,
            noAckElicitingPacketsInFlight: false,
            peerAddressValidationComplete: false,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TrySelectLossDetectionTimerMicros_LeavesAnExpiredTimerBlockedForZeroLengthDatagrams()
    {
        QuicAntiAmplificationBudget budget = CreateBlockedBudget();

        Assert.True(budget.TryRegisterReceivedDatagramPayloadBytes(0, uniquelyAttributedToSingleConnection: true));
        Assert.Equal(0UL, budget.RemainingSendBudget);

        Assert.False(QuicRecoveryTiming.TrySelectLossDetectionTimerMicros(
            earliestPendingLossTimeMicros: null,
            probeTimeoutMicros: 0,
            serverAtAntiAmplificationLimit: budget.RemainingSendBudget == 0,
            noAckElicitingPacketsInFlight: false,
            peerAddressValidationComplete: false,
            out _));
    }

    private static QuicAntiAmplificationBudget CreateBlockedBudget()
    {
        QuicAntiAmplificationBudget budget = new();
        Assert.True(budget.TryRegisterReceivedDatagramPayloadBytes(100, uniquelyAttributedToSingleConnection: true));
        Assert.True(budget.TryConsumeSendBudget(300));
        Assert.Equal(0UL, budget.RemainingSendBudget);
        return budget;
    }
}
