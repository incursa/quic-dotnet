// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S5P1P2-0009")]
public sealed class REQ_QUIC_RFC9000_S5P1P2_0009
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void IssuedConnectionIdRouteRemainsAcceptedUntilPeerRetiresIt()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath(
            peerActiveConnectionIdLimit: 3);
        QuicConnectionPathIdentity activePath = runtime.ActivePath!.Value.Identity;
        byte[] issuedConnectionId = [0x60, 0x61, 0x62, 0x63];

        QuicConnectionTransitionResult issued = runtime.Transition(
            new QuicConnectionConnectionIdIssuedEvent(
                ObservedAtTicks: 9,
                ConnectionId: 1UL,
                StatelessResetToken: QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0x60),
                ConnectionIdBytes: issuedConnectionId),
            nowTicks: 9);

        Assert.Contains(
            issued.Effects,
            effect => effect is QuicConnectionRegisterConnectionIdRouteEffect register
                && register.ConnectionId == 1UL
                && register.ConnectionIdBytes.Span.SequenceEqual(issuedConnectionId));
        Assert.DoesNotContain(
            issued.Effects,
            effect => effect is QuicConnectionRetireConnectionIdRouteEffect retire
                && retire.ConnectionId == 1UL);

        byte[] retirePayload = QuicFrameTestData.BuildRetireConnectionIdFrame(new QuicRetireConnectionIdFrame(1UL));
        QuicConnectionTransitionResult retired = QuicS19P16RetireConnectionIdTestSupport.TransitionOneRttPacket(
            runtime,
            activePath,
            runtime.CurrentPeerDestinationConnectionId.Span,
            retirePayload,
            observedAtTicks: 10);

        Assert.Contains(
            retired.Effects,
            effect => effect is QuicConnectionRetireConnectionIdRouteEffect retire
                && retire.ConnectionId == 1UL
                && retire.ConnectionIdBytes.Span.SequenceEqual(issuedConnectionId));
    }
}
