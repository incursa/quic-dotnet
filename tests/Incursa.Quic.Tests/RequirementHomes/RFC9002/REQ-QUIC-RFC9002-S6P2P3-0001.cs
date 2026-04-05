namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P2P3-0001">To speed up handshake completion under these conditions, an endpoint MAY, for a limited number of times per connection, send a packet containing unacknowledged CRYPTO data earlier than PTO expiry, subject to the address-validation limits.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S6P2P3-0001")]
public sealed class REQ_QUIC_RFC9002_S6P2P3_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TrySelectLossDetectionTimerMicros_ArmsAnEarlyCryptoProbeAfterUniqueDatagramReceiptRestoresSendBudget()
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

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TrySelectLossDetectionTimerMicros_DoesNotArmAnEarlyCryptoProbeWhileThePeerIsStillAmplificationLimited()
    {
        QuicAntiAmplificationBudget budget = CreateBlockedBudget();

        Assert.False(budget.CanSend(1));

        Assert.False(QuicRecoveryTiming.TrySelectLossDetectionTimerMicros(
            earliestPendingLossTimeMicros: null,
            probeTimeoutMicros: 2_800,
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
