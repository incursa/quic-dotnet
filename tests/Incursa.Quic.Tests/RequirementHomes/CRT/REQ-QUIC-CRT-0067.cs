namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0067")]
public sealed class REQ_QUIC_CRT_0067
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void CandidatePathValidationDoesNotSendWhenAmplificationBudgetIsInsufficient()
    {
        FakeMonotonicClock clock = new(0);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);

        QuicConnectionPathIdentity activePath = new("203.0.113.40", RemotePort: 443);
        QuicConnectionPathIdentity changedPath = new("203.0.113.41", RemotePort: 443);

        runtime.Transition(
            new QuicConnectionPacketReceivedEvent(ObservedAtTicks: 10, activePath, ReadOnlyMemory<byte>.Empty),
            nowTicks: 10);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(ObservedAtTicks: 20, changedPath, ReadOnlyMemory<byte>.Empty),
            nowTicks: 20);

        Assert.True(result.StateChanged);
        Assert.True(runtime.CandidatePaths.TryGetValue(changedPath, out QuicConnectionCandidatePathRecord candidatePath));
        Assert.False(candidatePath.Validation.IsValidated);
        Assert.False(candidatePath.Validation.IsAbandoned);
        Assert.Equal(0UL, candidatePath.Validation.ChallengeSendCount);
        Assert.Equal(0UL, candidatePath.AmplificationState.RemainingSendBudget);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionSendDatagramEffect);
    }

    private sealed class FakeMonotonicClock : IMonotonicClock
    {
        public FakeMonotonicClock(long ticks)
        {
            Ticks = ticks;
        }

        public long Ticks { get; }

        public double Seconds => Ticks / (double)TimeSpan.TicksPerSecond;
    }
}
