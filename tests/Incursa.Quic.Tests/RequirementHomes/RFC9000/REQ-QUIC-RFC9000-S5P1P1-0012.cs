// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S5P1P1-0012")]
public sealed class REQ_QUIC_RFC9000_S5P1P1_0012
{
    [Fact]
    /// <workbench-requirements generated="true" source="manual">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1P1-0012">An endpoint MUST NOT provide more connection IDs than the peer's limit.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S5P1P1-0012")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ConnectionIdIssuedEvent_AllowsOneAdditionalConnectionIdAtTheDefaultPeerLimit()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionConnectionIdIssuedEvent(
                ObservedAtTicks: 0,
                ConnectionId: 1UL,
                StatelessResetToken: QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0x30)),
            nowTicks: 0);

        Assert.True(result.StateChanged);
        Assert.Contains(
            result.Effects,
            effect => effect is QuicConnectionRegisterStatelessResetTokenEffect register && register.ConnectionId == 1UL);
    }

    [Fact]
    /// <workbench-requirements generated="true" source="manual">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1P1-0012">An endpoint MUST NOT provide more connection IDs than the peer's limit.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S5P1P1-0012")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ConnectionIdIssuedEvent_RejectsAnAdditionalConnectionIdThatWouldExceedTheDefaultPeerLimit()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();

        Assert.True(runtime.Transition(
            new QuicConnectionConnectionIdIssuedEvent(
                ObservedAtTicks: 0,
                ConnectionId: 1UL,
                StatelessResetToken: QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0x40)),
            nowTicks: 0).StateChanged);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionConnectionIdIssuedEvent(
                ObservedAtTicks: 1,
                ConnectionId: 2UL,
                StatelessResetToken: QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0x50)),
            nowTicks: 1);

        Assert.False(result.StateChanged);
        Assert.DoesNotContain(
            result.Effects,
            effect => effect is QuicConnectionRegisterStatelessResetTokenEffect register && register.ConnectionId == 2UL);
    }
}
