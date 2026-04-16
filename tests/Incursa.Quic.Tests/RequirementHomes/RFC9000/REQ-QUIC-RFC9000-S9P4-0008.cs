namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P4-0008")]
public sealed class REQ_QUIC_RFC9000_S9P4_0008
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ValidatingANewPathArmsASeparatePathValidationTimerThatCancelsOnSuccess()
    {
        QuicConnectionPathIdentity activePath = new("203.0.113.10", RemotePort: 443);
        QuicConnectionPathIdentity candidatePath = new("203.0.113.11", RemotePort: 443);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(activePath);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        QuicConnectionTransitionResult firstResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                candidatePath,
                datagram),
            nowTicks: 20);

        QuicConnectionSendDatagramEffect sendEffect = Assert.Single(
            firstResult.Effects.OfType<QuicConnectionSendDatagramEffect>());

        Assert.Equal(candidatePath, sendEffect.PathIdentity);
        Assert.True(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.PathValidation).HasValue);
        Assert.Null(runtime.SendRuntime.LossDetectionDeadlineMicros);

        long validationDeadlineTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.PathValidation)!.Value;
        QuicConnectionTransitionResult validationResult = runtime.Transition(
            new QuicConnectionPathValidationSucceededEvent(
                ObservedAtTicks: validationDeadlineTicks - 1,
                candidatePath),
            nowTicks: validationDeadlineTicks - 1);

        Assert.Contains(validationResult.Effects, effect =>
            effect is QuicConnectionCancelTimerEffect cancel
            && cancel.TimerKind == QuicConnectionTimerKind.PathValidation);
        Assert.Null(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.PathValidation));
    }
}
