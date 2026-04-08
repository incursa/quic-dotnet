namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0063")]
public sealed class REQ_QUIC_CRT_0063
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PacketFromANewAddressBeforeHandshakeConfirmationCreatesACandidatePathAndProbe()
    {
        FakeMonotonicClock clock = new(0);
        QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);

        QuicConnectionPathIdentity activePath = new("203.0.113.10", RemotePort: 443);
        QuicConnectionPathIdentity candidatePathIdentity = new("203.0.113.11", RemotePort: 443);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        runtime.Transition(
            new QuicConnectionPacketReceivedEvent(ObservedAtTicks: 10, activePath, datagram),
            nowTicks: 10);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(ObservedAtTicks: 20, candidatePathIdentity, datagram),
            nowTicks: 20);

        Assert.False(runtime.HandshakeConfirmed);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);

        Assert.True(runtime.CandidatePaths.TryGetValue(candidatePathIdentity, out QuicConnectionCandidatePathRecord candidatePath));
        Assert.False(candidatePath.Validation.IsValidated);
        Assert.False(candidatePath.Validation.IsAbandoned);
        Assert.Equal(1UL, candidatePath.Validation.ChallengeSendCount);
        Assert.True(candidatePath.Validation.ValidationDeadlineTicks.HasValue);
        Assert.Equal(QuicPathValidation.PathChallengeDataLength, candidatePath.Validation.ChallengePayload.Length);
        Assert.Equal((ulong)QuicVersionNegotiation.Version1MinimumDatagramPayloadSize, candidatePath.AmplificationState.ReceivedPayloadBytes);
        Assert.Equal((ulong)QuicVersionNegotiation.Version1MinimumDatagramPayloadSize, candidatePath.AmplificationState.SentPayloadBytes);
        Assert.False(candidatePath.AmplificationState.IsAddressValidated);

        Assert.True(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.PathValidation).HasValue);
        Assert.Contains(result.Effects, effect =>
            effect is QuicConnectionEmitDiagnosticEffect diagnostic
            && diagnostic.Message.Contains(QuicConnectionPathClassification.ProbableNatRebinding.ToString(), StringComparison.Ordinal));
        Assert.Contains(result.Effects, effect =>
            effect is QuicConnectionSendDatagramEffect send
            && send.PathIdentity == candidatePathIdentity
            && send.Datagram.Length == QuicVersionNegotiation.Version1MinimumDatagramPayloadSize);
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
