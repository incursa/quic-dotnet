// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S5P1P1-0017")]
public sealed class REQ_QUIC_RFC9000_S5P1P1_0017
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ConnectionIdIssuedEvent_StopsIssuingAfterTheConfiguredTotalLimit()
    {
        using QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            maximumLocallyIssuedConnectionIds: 1);

        QuicConnectionTransitionResult firstIssue = runtime.Transition(
            new QuicConnectionConnectionIdIssuedEvent(
                ObservedAtTicks: 0,
                ConnectionId: 1UL,
                StatelessResetToken: QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0xA0),
                ConnectionIdBytes: new byte[] { 0xA1, 0xA2, 0xA3 }),
            nowTicks: 0);

        Assert.True(firstIssue.StateChanged);
        Assert.Contains(
            firstIssue.Effects,
            effect => effect is QuicConnectionRegisterConnectionIdRouteEffect register
                && register.ConnectionId == 1UL);

        QuicConnectionTransitionResult retirement = runtime.Transition(
            new QuicConnectionConnectionIdRetiredEvent(
                ObservedAtTicks: 1,
                ConnectionId: 1UL),
            nowTicks: 1);

        Assert.True(retirement.StateChanged);
        Assert.Contains(
            retirement.Effects,
            effect => effect is QuicConnectionRetireConnectionIdRouteEffect retire
                && retire.ConnectionId == 1UL);

        QuicConnectionTransitionResult secondIssue = runtime.Transition(
            new QuicConnectionConnectionIdIssuedEvent(
                ObservedAtTicks: 2,
                ConnectionId: 2UL,
                StatelessResetToken: QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0xB0),
                ConnectionIdBytes: new byte[] { 0xB1, 0xB2, 0xB3 }),
            nowTicks: 2);

        Assert.False(secondIssue.StateChanged);
        Assert.DoesNotContain(
            secondIssue.Effects,
            effect => effect is QuicConnectionRegisterConnectionIdRouteEffect);
        Assert.DoesNotContain(
            secondIssue.Effects,
            effect => effect is QuicConnectionRegisterStatelessResetTokenEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RetireConnectionIdFrame_DoesNotReplenishAfterTheConfiguredTotalLimit()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath(
            peerActiveConnectionIdLimit: 3,
            maximumLocallyIssuedConnectionIds: 1);
        byte[] issuedConnectionId = [0xC1, 0xC2, 0xC3, 0xC4];

        Assert.True(runtime.Transition(
            new QuicConnectionConnectionIdIssuedEvent(
                ObservedAtTicks: 9,
                ConnectionId: 1UL,
                StatelessResetToken: QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0xC0),
                ConnectionIdBytes: issuedConnectionId),
            nowTicks: 9).StateChanged);

        byte[] retirePayload = QuicFrameTestData.BuildRetireConnectionIdFrame(new QuicRetireConnectionIdFrame(1UL));
        QuicConnectionTransitionResult result = QuicS19P16RetireConnectionIdTestSupport.TransitionOneRttPacket(
            runtime,
            runtime.ActivePath!.Value.Identity,
            issuedConnectionId,
            retirePayload,
            observedAtTicks: 10);

        Assert.True(result.StateChanged);
        Assert.Contains(
            result.Effects,
            effect => effect is QuicConnectionRetireConnectionIdRouteEffect retire
                && retire.ConnectionId == 1UL);
        Assert.DoesNotContain(
            result.Effects,
            effect => effect is QuicConnectionRegisterConnectionIdRouteEffect);
        Assert.DoesNotContain(
            result.Effects,
            effect => effect is QuicConnectionRegisterStatelessResetTokenEffect);
        Assert.DoesNotContain(
            result.Effects,
            effect => effect is QuicConnectionSendDatagramEffect);
    }
}
