namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0052")]
public sealed class REQ_QUIC_CRT_0052
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RearmingAndCancellingATimerAdvanceItsGenerationCounter()
    {
        FakeMonotonicClock clock = new(0);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);

        QuicConnectionArmTimerEffect firstArm = Assert.IsType<QuicConnectionArmTimerEffect>(
            Assert.Single(runtime.SetTimerDeadline(QuicConnectionTimerKind.IdleTimeout, 10)));

        QuicConnectionArmTimerEffect secondArm = Assert.IsType<QuicConnectionArmTimerEffect>(
            Assert.Single(runtime.SetTimerDeadline(QuicConnectionTimerKind.IdleTimeout, 20)));

        QuicConnectionCancelTimerEffect cancelEffect = Assert.IsType<QuicConnectionCancelTimerEffect>(
            Assert.Single(runtime.SetTimerDeadline(QuicConnectionTimerKind.IdleTimeout, null)));

        Assert.Equal(1UL, firstArm.Generation);
        Assert.Equal(2UL, secondArm.Generation);
        Assert.Equal(3UL, cancelEffect.Generation);
        Assert.Null(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.IdleTimeout));
        Assert.Equal(cancelEffect.Generation, runtime.TimerState.GetGeneration(QuicConnectionTimerKind.IdleTimeout));
    }
}
