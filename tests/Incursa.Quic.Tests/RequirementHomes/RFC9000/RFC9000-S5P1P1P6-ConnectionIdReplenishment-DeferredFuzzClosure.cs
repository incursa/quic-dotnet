// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class RFC9000_S5P1P1P6_ConnectionIdReplenishment_DeferredFuzzClosure
{
    [Theory]
    [InlineData(3UL, 0xB0)]
    [InlineData(4UL, 0xC0)]
    [Requirement("RFC9000-S5-1-1-P6-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void RetireConnectionIdFuzz_SuppliesReplacementWhenIssuanceCapacityRemains(
        ulong peerActiveConnectionIdLimit,
        int seed)
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath(
            peerActiveConnectionIdLimit: peerActiveConnectionIdLimit);
        byte[] retiredConnectionId = CreateConnectionId(seed);

        Assert.True(runtime.Transition(
            new QuicConnectionConnectionIdIssuedEvent(
                ObservedAtTicks: 0,
                ConnectionId: 1UL,
                StatelessResetToken: QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(unchecked((byte)(seed + 0x10))),
                ConnectionIdBytes: retiredConnectionId),
            nowTicks: 0).StateChanged);

        QuicConnectionTransitionResult result = QuicS19P16RetireConnectionIdTestSupport.TransitionOneRttPacket(
            runtime,
            runtime.ActivePath!.Value.Identity,
            retiredConnectionId,
            QuicFrameTestData.BuildRetireConnectionIdFrame(new QuicRetireConnectionIdFrame(1UL)),
            observedAtTicks: 1);

        Assert.True(result.StateChanged);
        Assert.Contains(result.Effects, effect =>
            effect is QuicConnectionRetireConnectionIdRouteEffect retire
            && retire.ConnectionId == 1UL
            && retire.ConnectionIdBytes.Span.SequenceEqual(retiredConnectionId));
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
        Assert.True(replacementRoute.ConnectionIdBytes.Span.SequenceEqual(replacementFrame.ConnectionId));
        Assert.True(replacementToken.Token.Span.SequenceEqual(replacementFrame.StatelessResetToken));
    }

    [Theory]
    [InlineData(3UL, 0xD0)]
    [InlineData(4UL, 0xE0)]
    [Requirement("RFC9000-S5-1-1-P6-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void PreviouslyUnusedConnectionIdFuzz_ReplenishesOnlyOnFirstUse(
        ulong peerActiveConnectionIdLimit,
        int seed)
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath(
            peerActiveConnectionIdLimit: peerActiveConnectionIdLimit);
        byte[] issuedConnectionId = CreateConnectionId(seed);

        Assert.True(runtime.Transition(
            new QuicConnectionConnectionIdIssuedEvent(
                ObservedAtTicks: 9,
                ConnectionId: 1UL,
                StatelessResetToken: QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(unchecked((byte)(seed + 0x10))),
                ConnectionIdBytes: issuedConnectionId),
            nowTicks: 9).StateChanged);

        QuicConnectionTransitionResult firstUse = QuicConnectionIdLifecycleTestSupport.TransitionOneRttPacket(
            runtime,
            runtime.ActivePath!.Value.Identity,
            issuedConnectionId,
            QuicFrameTestData.BuildPingFrame(),
            routedLocallyIssuedConnectionId: 1UL,
            observedAtTicks: 10);

        Assert.True(firstUse.StateChanged);
        Assert.Contains(firstUse.Effects, effect =>
            effect is QuicConnectionRegisterConnectionIdRouteEffect register
            && register.ConnectionId == 2UL);
        Assert.Single(QuicConnectionIdLifecycleTestSupport.GetNewConnectionIdFrames(runtime, firstUse));

        QuicConnectionTransitionResult repeatedUse = QuicConnectionIdLifecycleTestSupport.TransitionOneRttPacket(
            runtime,
            runtime.ActivePath!.Value.Identity,
            issuedConnectionId,
            QuicFrameTestData.BuildPingFrame(),
            routedLocallyIssuedConnectionId: 1UL,
            observedAtTicks: 11);

        Assert.DoesNotContain(repeatedUse.Effects, effect => effect is QuicConnectionRegisterConnectionIdRouteEffect);
        Assert.DoesNotContain(repeatedUse.Effects, effect => effect is QuicConnectionRegisterStatelessResetTokenEffect);
        Assert.Empty(QuicConnectionIdLifecycleTestSupport.GetNewConnectionIdFrames(runtime, repeatedUse));
    }

    private static byte[] CreateConnectionId(int seed)
    {
        byte[] connectionId = new byte[4];
        for (int index = 0; index < connectionId.Length; index++)
        {
            connectionId[index] = unchecked((byte)(seed + index));
        }

        return connectionId;
    }
}
