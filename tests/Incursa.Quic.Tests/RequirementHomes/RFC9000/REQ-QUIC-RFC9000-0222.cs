namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0222")]
public sealed class REQ_QUIC_RFC9000_0222
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RetiredIssuedConnectionIdIsReplenishedWithTheNextSequenceNumber()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath(
            peerActiveConnectionIdLimit: 3);
        byte[] issuedConnectionId = [0x70, 0x71, 0x72, 0x73];

        Assert.True(runtime.Transition(
            new QuicConnectionConnectionIdIssuedEvent(
                ObservedAtTicks: 0,
                ConnectionId: 1UL,
                StatelessResetToken: QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0x70),
                ConnectionIdBytes: issuedConnectionId),
            nowTicks: 0).StateChanged);

        QuicConnectionTransitionResult result = QuicS19P16RetireConnectionIdTestSupport.TransitionOneRttPacket(
            runtime,
            runtime.ActivePath!.Value.Identity,
            issuedConnectionId,
            QuicFrameTestData.BuildRetireConnectionIdFrame(new QuicRetireConnectionIdFrame(1UL)),
            observedAtTicks: 1);

        QuicNewConnectionIdFrameProofSnapshot replacementFrame =
            Assert.Single(QuicConnectionIdLifecycleTestSupport.GetNewConnectionIdFrames(runtime, result));

        Assert.Equal(2UL, replacementFrame.SequenceNumber);
        Assert.Equal(0UL, replacementFrame.RetirePriorTo);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DuplicateIssuedConnectionIdSequenceNumberIsRejected()
    {
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());

        Assert.True(runtime.Transition(
            new QuicConnectionConnectionIdIssuedEvent(
                ObservedAtTicks: 0,
                ConnectionId: 1UL,
                StatelessResetToken: QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0x80),
                ConnectionIdBytes: new byte[] { 0x80, 0x81, 0x82 }),
            nowTicks: 0).StateChanged);

        QuicConnectionTransitionResult duplicate = runtime.Transition(
            new QuicConnectionConnectionIdIssuedEvent(
                ObservedAtTicks: 1,
                ConnectionId: 1UL,
                StatelessResetToken: QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0x90),
                ConnectionIdBytes: new byte[] { 0x90, 0x91, 0x92 }),
            nowTicks: 1);

        Assert.False(duplicate.StateChanged);
        Assert.DoesNotContain(
            duplicate.Effects,
            effect => effect is QuicConnectionRegisterConnectionIdRouteEffect);
        Assert.DoesNotContain(
            duplicate.Effects,
            effect => effect is QuicConnectionRegisterStatelessResetTokenEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ReplenishmentDoesNotWrapAfterTheMaximumVariableLengthSequenceNumber()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath(
            peerActiveConnectionIdLimit: 3);
        byte[] issuedConnectionId = [0xA0, 0xA1, 0xA2, 0xA3];

        Assert.True(runtime.Transition(
            new QuicConnectionConnectionIdIssuedEvent(
                ObservedAtTicks: 0,
                ConnectionId: QuicVariableLengthInteger.MaxValue,
                StatelessResetToken: QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0xA0),
                ConnectionIdBytes: issuedConnectionId),
            nowTicks: 0).StateChanged);

        QuicConnectionTransitionResult result = QuicS19P16RetireConnectionIdTestSupport.TransitionOneRttPacket(
            runtime,
            runtime.ActivePath!.Value.Identity,
            issuedConnectionId,
            QuicFrameTestData.BuildRetireConnectionIdFrame(new QuicRetireConnectionIdFrame(QuicVariableLengthInteger.MaxValue)),
            observedAtTicks: 1);

        Assert.True(result.StateChanged);
        Assert.Contains(
            result.Effects,
            effect => effect is QuicConnectionRetireConnectionIdRouteEffect retire
                && retire.ConnectionId == QuicVariableLengthInteger.MaxValue);
        Assert.Empty(QuicConnectionIdLifecycleTestSupport.GetNewConnectionIdFrames(runtime, result));
        Assert.DoesNotContain(
            result.Effects,
            effect => effect is QuicConnectionRegisterConnectionIdRouteEffect);
    }
}
