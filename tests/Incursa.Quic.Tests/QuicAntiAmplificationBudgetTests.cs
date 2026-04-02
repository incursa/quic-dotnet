namespace Incursa.Quic.Tests;

public sealed class QuicAntiAmplificationBudgetTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S14P1-0008")]
    [Requirement("REQ-QUIC-RFC9000-S8-0001")]
    [Requirement("REQ-QUIC-RFC9000-S8P1-0002")]
    [Requirement("REQ-QUIC-RFC9000-S9P3P1-0001")]
    [Trait("Category", "Positive")]
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
    [Requirement("REQ-QUIC-RFC9000-S8-0001")]
    [Trait("Category", "Negative")]
    public void TryRegisterReceivedDatagramPayloadBytes_RejectsNegativePayloadLengths()
    {
        QuicAntiAmplificationBudget budget = new();

        Assert.False(budget.TryRegisterReceivedDatagramPayloadBytes(-1, uniquelyAttributedToSingleConnection: true));
        Assert.Equal(0UL, budget.ReceivedPayloadBytes);
        Assert.False(budget.CanSend(-1));
        Assert.False(budget.TryConsumeSendBudget(-1));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S8P1-0003")]
    [Trait("Category", "Positive")]
    public void TryRegisterReceivedDatagramPayloadBytes_IgnoresDatagramsThatAreNotUniquelyAttributed()
    {
        QuicAntiAmplificationBudget budget = new();

        Assert.True(budget.TryRegisterReceivedDatagramPayloadBytes(100, uniquelyAttributedToSingleConnection: true));
        Assert.True(budget.TryRegisterReceivedDatagramPayloadBytes(50, uniquelyAttributedToSingleConnection: false));

        Assert.Equal(100UL, budget.ReceivedPayloadBytes);
        Assert.Equal(300UL, budget.RemainingSendBudget);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S14P1-0008")]
    [Requirement("REQ-QUIC-RFC9000-S8-0001")]
    [Requirement("REQ-QUIC-RFC9000-S9P3P1-0001")]
    [Trait("Category", "Positive")]
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
