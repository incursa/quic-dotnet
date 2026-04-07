namespace Incursa.Quic.Tests;

public sealed class QuicAntiAmplificationBudgetTests
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void CanSend_TracksTheThreeTimesAmplificationCapUntilValidation()
    {
        QuicAntiAmplificationBudget budget = new();

        Assert.True(budget.TryRegisterReceivedDatagramPayloadBytes(100, uniquelyAttributedToSingleConnection: true));
        Assert.Equal(100UL, budget.ReceivedPayloadBytes);
        Assert.Equal(300UL, budget.RemainingSendBudget);
        Assert.True(budget.CanSend(300));
        Assert.False(budget.CanSend(301));

        Assert.True(budget.TryConsumeSendBudget(300));
        Assert.Equal(300UL, budget.SentPayloadBytes);
        Assert.Equal(0UL, budget.RemainingSendBudget);
        Assert.False(budget.CanSend(1));
        Assert.False(budget.TryConsumeSendBudget(1));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryConsumeSendBudget_RejectsPayloadsThatExceedTheRemainingBudget()
    {
        QuicAntiAmplificationBudget budget = new();

        Assert.True(budget.TryRegisterReceivedDatagramPayloadBytes(100, uniquelyAttributedToSingleConnection: true));
        Assert.Equal(300UL, budget.RemainingSendBudget);

        Assert.False(budget.CanSend(301));
        Assert.False(budget.TryConsumeSendBudget(301));
        Assert.Equal(100UL, budget.ReceivedPayloadBytes);
        Assert.Equal(0UL, budget.SentPayloadBytes);
        Assert.Equal(300UL, budget.RemainingSendBudget);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void CanSend_AllowsUnlimitedSendingAfterAddressValidation()
    {
        QuicAntiAmplificationBudget budget = new();

        budget.MarkAddressValidated();

        Assert.True(budget.IsAddressValidated);
        Assert.True(budget.CanSend(int.MaxValue));
        Assert.True(budget.TryConsumeSendBudget(int.MaxValue));
        Assert.Equal((ulong)int.MaxValue, budget.SentPayloadBytes);
        Assert.Equal(ulong.MaxValue, budget.RemainingSendBudget);
    }
}
