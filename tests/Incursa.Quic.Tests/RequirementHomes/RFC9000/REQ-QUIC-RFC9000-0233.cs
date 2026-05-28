// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0233")]
public sealed class REQ_QUIC_RFC9000_0233
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RetireConnectionIdFrame_DoesNotSupplyAReplacementAfterTheLocalIssuanceCap()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath(
            peerActiveConnectionIdLimit: 3,
            maximumLocallyIssuedConnectionIds: 1);
        byte[] retiredConnectionId = [0xC0, 0xC1, 0xC2, 0xC3];

        Assert.True(runtime.Transition(
            new QuicConnectionConnectionIdIssuedEvent(
                ObservedAtTicks: 0,
                ConnectionId: 1UL,
                StatelessResetToken: QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0xC0),
                ConnectionIdBytes: retiredConnectionId),
            nowTicks: 0).StateChanged);

        QuicConnectionTransitionResult result = QuicS19P16RetireConnectionIdTestSupport.TransitionOneRttPacket(
            runtime,
            runtime.ActivePath!.Value.Identity,
            retiredConnectionId,
            QuicFrameTestData.BuildRetireConnectionIdFrame(new QuicRetireConnectionIdFrame(1UL)),
            observedAtTicks: 1);

        Assert.True(result.StateChanged);
        Assert.Contains(
            result.Effects,
            effect => effect is QuicConnectionRetireConnectionIdRouteEffect retire
                && retire.ConnectionId == 1UL
                && retire.ConnectionIdBytes.Span.SequenceEqual(retiredConnectionId));
        Assert.DoesNotContain(
            result.Effects,
            effect => effect is QuicConnectionRegisterConnectionIdRouteEffect);
        Assert.DoesNotContain(
            result.Effects,
            effect => effect is QuicConnectionRegisterStatelessResetTokenEffect);
        Assert.Empty(QuicConnectionIdLifecycleTestSupport.GetNewConnectionIdFrames(runtime, result));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RetireConnectionIdFrameSuppliesAReplacementConnectionId()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath(
            peerActiveConnectionIdLimit: 3);
        byte[] retiredConnectionId = [0xB0, 0xB1, 0xB2, 0xB3];

        Assert.True(runtime.Transition(
            new QuicConnectionConnectionIdIssuedEvent(
                ObservedAtTicks: 0,
                ConnectionId: 1UL,
                StatelessResetToken: QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0xB0),
                ConnectionIdBytes: retiredConnectionId),
            nowTicks: 0).StateChanged);

        QuicConnectionTransitionResult result = QuicS19P16RetireConnectionIdTestSupport.TransitionOneRttPacket(
            runtime,
            runtime.ActivePath!.Value.Identity,
            retiredConnectionId,
            QuicFrameTestData.BuildRetireConnectionIdFrame(new QuicRetireConnectionIdFrame(1UL)),
            observedAtTicks: 1);

        Assert.True(result.StateChanged);
        Assert.Contains(
            result.Effects,
            effect => effect is QuicConnectionRetireConnectionIdRouteEffect retire
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
        Assert.True(replacementRoute.ConnectionIdBytes.Span.SequenceEqual(replacementFrame.ConnectionId));
        Assert.True(replacementToken.Token.Span.SequenceEqual(replacementFrame.StatelessResetToken));
    }
}
