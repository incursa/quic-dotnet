// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S5-1-2-P7-S1-R01")]
public sealed class REQ_QUIC_RFC9000_0253
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ReplacementNewConnectionIdFrame_DoesNotIncreaseRetirePriorToBeforePeerRetirement()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath(
            peerActiveConnectionIdLimit: 3);
        byte[] issuedConnectionId = [0xB0, 0xB1, 0xB2, 0xB3];

        Assert.True(runtime.Transition(
            new QuicConnectionConnectionIdIssuedEvent(
                ObservedAtTicks: 9,
                ConnectionId: 1UL,
                StatelessResetToken: QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0xB0),
                ConnectionIdBytes: issuedConnectionId),
            nowTicks: 9).StateChanged);

        byte[] packet = QuicConnectionIdLifecycleTestSupport.BuildOneRttPacket(
            runtime,
            issuedConnectionId,
            QuicFrameTestData.BuildPingFrame());

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 10,
                runtime.ActivePath!.Value.Identity,
                packet,
                RoutedLocallyIssuedConnectionId: 1UL),
            nowTicks: 10);

        QuicNewConnectionIdFrameProofSnapshot replacementFrame =
            Assert.Single(QuicConnectionIdLifecycleTestSupport.GetNewConnectionIdFrames(runtime, result));
        Assert.Equal(2UL, replacementFrame.SequenceNumber);
        Assert.Equal(0UL, replacementFrame.RetirePriorTo);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void SaturatedPeerActiveConnectionIdLimitDoesNotEmitPrematureRetirePriorToUpdate()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath(
            peerActiveConnectionIdLimit: 2);
        byte[] issuedConnectionId = [0xC0, 0xC1, 0xC2, 0xC3];

        Assert.True(runtime.Transition(
            new QuicConnectionConnectionIdIssuedEvent(
                ObservedAtTicks: 9,
                ConnectionId: 1UL,
                StatelessResetToken: QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0xC0),
                ConnectionIdBytes: issuedConnectionId),
            nowTicks: 9).StateChanged);

        byte[] packet = QuicConnectionIdLifecycleTestSupport.BuildOneRttPacket(
            runtime,
            issuedConnectionId,
            QuicFrameTestData.BuildPingFrame());

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 10,
                runtime.ActivePath!.Value.Identity,
                packet,
                RoutedLocallyIssuedConnectionId: 1UL),
            nowTicks: 10);

        Assert.Empty(QuicConnectionIdLifecycleTestSupport.GetNewConnectionIdFrames(runtime, result));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void PeerRetirementReplenishmentStillUsesZeroRetirePriorTo()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath(
            peerActiveConnectionIdLimit: 3);
        byte[] issuedConnectionId = [0xD0, 0xD1, 0xD2, 0xD3];

        Assert.True(runtime.Transition(
            new QuicConnectionConnectionIdIssuedEvent(
                ObservedAtTicks: 9,
                ConnectionId: 1UL,
                StatelessResetToken: QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0xD0),
                ConnectionIdBytes: issuedConnectionId),
            nowTicks: 9).StateChanged);

        byte[] retirePayload = QuicFrameTestData.BuildRetireConnectionIdFrame(new QuicRetireConnectionIdFrame(1UL));
        QuicConnectionTransitionResult result = QuicS19P16RetireConnectionIdTestSupport.TransitionOneRttPacket(
            runtime,
            runtime.ActivePath!.Value.Identity,
            runtime.CurrentPeerDestinationConnectionId.Span,
            retirePayload,
            observedAtTicks: 10);

        QuicNewConnectionIdFrameProofSnapshot replacementFrame =
            Assert.Single(QuicConnectionIdLifecycleTestSupport.GetNewConnectionIdFrames(runtime, result));
        Assert.Equal(2UL, replacementFrame.SequenceNumber);
        Assert.Equal(0UL, replacementFrame.RetirePriorTo);
    }
}
