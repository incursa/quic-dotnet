namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0078")]
public sealed class REQ_QUIC_CRT_0078
{
    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void DrainingAfterClosingPreservesTheExistingTerminalEndTime()
    {
        QuicCrtLifecycleClock clock = new(0);
        using QuicConnectionRuntime runtime = QuicCrtLifecycleRequirementTestSupport.CreateRuntime(clock);

        QuicCrtLifecycleRequirementTestSupport.RequestLocalClose(
            runtime,
            QuicCrtLifecycleRequirementTestSupport.MicrosecondsToTicks(75));

        long closeDueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.CloseLifetime)!.Value;

        QuicConnectionTransitionResult result = QuicCrtLifecycleRequirementTestSupport.ReceivePeerClose(
            runtime,
            QuicCrtLifecycleRequirementTestSupport.MicrosecondsToTicks(100));

        Assert.Equal(QuicConnectionPhase.Draining, runtime.Phase);
        Assert.Null(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.CloseLifetime));
        Assert.Equal(closeDueTicks, runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.DrainLifetime));
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionSendDatagramEffect);
    }
}
