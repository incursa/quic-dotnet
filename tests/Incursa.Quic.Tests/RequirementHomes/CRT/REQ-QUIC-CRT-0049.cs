namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0049")]
public sealed class REQ_QUIC_CRT_0049
{
    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TimerPriorityUsesTheSequenceTieBreakerForEqualDeadlines()
    {
        QuicConnectionTimerPriority earlierSequence = new(1_000, 3);
        QuicConnectionTimerPriority laterSequence = new(1_000, 4);
        QuicConnectionTimerPriority earlierDueTick = new(999, 99);

        Assert.True(earlierSequence < laterSequence);
        Assert.True(earlierSequence <= laterSequence);
        Assert.True(laterSequence > earlierSequence);
        Assert.True(laterSequence >= earlierSequence);
        Assert.True(earlierDueTick < earlierSequence);
        Assert.True(earlierDueTick <= earlierSequence);
        Assert.Equal(0, earlierSequence.CompareTo(new QuicConnectionTimerPriority(1_000, 3)));
    }
}
