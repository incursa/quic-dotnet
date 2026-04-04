namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-SAP6-0001")]
public sealed class REQ_QUIC_RFC9002_SAP6_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TrySelectLossDetectionTimerMicros_ArmsTheTimerWhenReceivedDatagramRestoresSendBudget()
    {
        QuicAntiAmplificationBudget budget = CreateBlockedBudget();

        Assert.False(budget.CanSend(1));
        Assert.True(budget.TryRegisterReceivedDatagramPayloadBytes(1, uniquelyAttributedToSingleConnection: true));
        Assert.True(budget.CanSend(1));

        Assert.True(QuicRecoveryTiming.TrySelectLossDetectionTimerMicros(
            earliestPendingLossTimeMicros: null,
            probeTimeoutMicros: 2_800,
            serverAtAntiAmplificationLimit: budget.RemainingSendBudget == 0,
            noAckElicitingPacketsInFlight: false,
            peerAddressValidationComplete: false,
            out ulong selectedTimerMicros));

        Assert.Equal(2_800UL, selectedTimerMicros);
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
