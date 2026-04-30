namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0005")]
public sealed class REQ_QUIC_CRT_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ConnectionTransitionsReturnExplicitEndpointAndTimerEffects()
    {
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0x45);

        QuicConnectionTransitionResult issued = runtime.Transition(
            new QuicConnectionConnectionIdIssuedEvent(
                ObservedAtTicks: 10,
                ConnectionId: 45UL,
                StatelessResetToken: token),
            nowTicks: 10);

        QuicConnectionRegisterStatelessResetTokenEffect resetEffect = Assert.IsType<QuicConnectionRegisterStatelessResetTokenEffect>(
            Assert.Single(issued.Effects));

        Assert.Equal(45UL, resetEffect.ConnectionId);
        Assert.True(token.SequenceEqual(resetEffect.Token.Span));

        QuicConnectionArmTimerEffect timerEffect = Assert.IsType<QuicConnectionArmTimerEffect>(
            Assert.Single(runtime.SetTimerDeadline(QuicConnectionTimerKind.IdleTimeout, 1_000)));

        Assert.Equal(QuicConnectionTimerKind.IdleTimeout, timerEffect.TimerKind);
        Assert.Equal(1_000L, timerEffect.Priority.DueTicks);
    }
}
