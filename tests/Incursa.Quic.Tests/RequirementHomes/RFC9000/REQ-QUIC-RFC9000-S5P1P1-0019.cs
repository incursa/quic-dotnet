namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S5P1P1-0019")]
public sealed class REQ_QUIC_RFC9000_S5P1P1_0019
{
    private static readonly byte[] IssuedConnectionId =
    [
        0xD1, 0xD2, 0xD3, 0xD4,
    ];

    private static readonly QuicConnectionPathIdentity MigratedPath =
        new("203.0.113.230", RemotePort: 443);

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void MigratedPathPacketOnPreviouslyUnusedIssuedConnectionId_ReplenishesPeerUsableConnectionIdPool()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath(
            peerActiveConnectionIdLimit: 3);
        AssertIssuedConnectionId(runtime, IssuedConnectionId, observedAtTicks: 9);

        QuicConnectionTransitionResult result = QuicConnectionIdLifecycleTestSupport.TransitionOneRttPacket(
            runtime,
            MigratedPath,
            IssuedConnectionId,
            QuicFrameTestData.BuildPingFrame(),
            routedLocallyIssuedConnectionId: 1UL,
            observedAtTicks: 10);

        Assert.True(result.StateChanged);
        Assert.True(runtime.CandidatePaths.ContainsKey(MigratedPath));
        QuicConnectionRegisterConnectionIdRouteEffect replacementRoute =
            Assert.Single(result.Effects.OfType<QuicConnectionRegisterConnectionIdRouteEffect>());
        QuicConnectionRegisterStatelessResetTokenEffect replacementToken =
            Assert.Single(result.Effects.OfType<QuicConnectionRegisterStatelessResetTokenEffect>());
        QuicNewConnectionIdFrameProofSnapshot replacementFrame =
            Assert.Single(QuicConnectionIdLifecycleTestSupport.GetNewConnectionIdFrames(runtime, result));

        Assert.Equal(2UL, replacementRoute.ConnectionId);
        Assert.Equal(2UL, replacementToken.ConnectionId);
        Assert.Equal(2UL, replacementFrame.SequenceNumber);
        Assert.Equal(0UL, replacementFrame.RetirePriorTo);
        Assert.Equal(8, replacementRoute.ConnectionIdBytes.Length);
        Assert.Equal(QuicStatelessReset.StatelessResetTokenLength, replacementToken.Token.Length);
        Assert.Equal(replacementRoute.ConnectionIdBytes.ToArray(), replacementFrame.ConnectionId);
        Assert.Equal(replacementToken.Token.ToArray(), replacementFrame.StatelessResetToken);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void MigratedPathPacket_WhenPeerActiveConnectionIdLimitIsFull_DoesNotReplenishPool()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath(
            peerActiveConnectionIdLimit: 2);
        AssertIssuedConnectionId(runtime, IssuedConnectionId, observedAtTicks: 9);

        QuicConnectionTransitionResult result = QuicConnectionIdLifecycleTestSupport.TransitionOneRttPacket(
            runtime,
            MigratedPath,
            IssuedConnectionId,
            QuicFrameTestData.BuildPingFrame(),
            routedLocallyIssuedConnectionId: 1UL,
            observedAtTicks: 10);

        Assert.True(result.StateChanged);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionRegisterConnectionIdRouteEffect);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionRegisterStatelessResetTokenEffect);
        Assert.Empty(QuicConnectionIdLifecycleTestSupport.GetNewConnectionIdFrames(runtime, result));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void MigratedPathPacket_WhenLocalIssuanceBudgetIsExhausted_DoesNotReplenishPool()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath(
            peerActiveConnectionIdLimit: 3,
            maximumLocallyIssuedConnectionIds: 1);
        AssertIssuedConnectionId(runtime, IssuedConnectionId, observedAtTicks: 9);

        QuicConnectionTransitionResult result = QuicConnectionIdLifecycleTestSupport.TransitionOneRttPacket(
            runtime,
            MigratedPath,
            IssuedConnectionId,
            QuicFrameTestData.BuildPingFrame(),
            routedLocallyIssuedConnectionId: 1UL,
            observedAtTicks: 10);

        Assert.True(result.StateChanged);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionRegisterConnectionIdRouteEffect);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionRegisterStatelessResetTokenEffect);
        Assert.Empty(QuicConnectionIdLifecycleTestSupport.GetNewConnectionIdFrames(runtime, result));
    }

    private static void AssertIssuedConnectionId(
        QuicConnectionRuntime runtime,
        ReadOnlySpan<byte> connectionIdBytes,
        long observedAtTicks)
    {
        byte[] expectedConnectionIdBytes = connectionIdBytes.ToArray();
        QuicConnectionTransitionResult issued = runtime.Transition(
            new QuicConnectionConnectionIdIssuedEvent(
                ObservedAtTicks: observedAtTicks,
                ConnectionId: 1UL,
                StatelessResetToken: QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0xB0),
                ConnectionIdBytes: expectedConnectionIdBytes),
            nowTicks: observedAtTicks);

        Assert.True(issued.StateChanged);
        Assert.Contains(
            issued.Effects,
            effect => effect is QuicConnectionRegisterConnectionIdRouteEffect route
                && route.ConnectionId == 1UL
                && route.ConnectionIdBytes.Span.SequenceEqual(expectedConnectionIdBytes));
        Assert.Contains(
            issued.Effects,
            effect => effect is QuicConnectionRegisterStatelessResetTokenEffect token
                && token.ConnectionId == 1UL);
    }
}
