// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S5P1P2-0008")]
public sealed class REQ_QUIC_RFC9000_S5P1P2_0008
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void NewConnectionIdFrame_WithIncreasedRetirePriorToPromptsPeerConnectionIdRetirement()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();

        Assert.True(QuicConnectionIdLifecycleTestSupport.ProcessNewConnectionIdFrame(
            runtime,
            sequenceNumber: 1UL,
            retirePriorTo: 0UL,
            connectionId: [0x10, 0x11, 0x12],
            observedAtTicks: 9,
            statelessResetTokenStart: 0x20).StateChanged);

        QuicConnectionTransitionResult result = QuicConnectionIdLifecycleTestSupport.ProcessNewConnectionIdFrame(
            runtime,
            sequenceNumber: 2UL,
            retirePriorTo: 1UL,
            connectionId: [0x20, 0x21, 0x22],
            observedAtTicks: 10,
            statelessResetTokenStart: 0x30);

        Assert.True(result.StateChanged);
        Assert.Equal([0UL], QuicConnectionIdLifecycleTestSupport.GetRetiredSequenceNumbers(runtime, result));
        Assert.Equal([0x20, 0x21, 0x22], runtime.CurrentPeerDestinationConnectionId.ToArray());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void NewConnectionIdFrame_WithoutIncreasedRetirePriorToDoesNotPromptRetirement()
    {
        QuicConnectionPeerConnectionIdState state = new();

        Assert.True(QuicConnectionIdLifecycleTestSupport.TryAcceptNewConnectionId(
            state,
            sequenceNumber: 1UL,
            retirePriorTo: 0UL,
            connectionIdStart: 0x30,
            activeConnectionIdLimit: 3UL,
            out QuicTransportErrorCode errorCode,
            out _,
            out ulong[] retiredSequenceNumbers));

        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        Assert.Empty(retiredSequenceNumbers);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void NewConnectionIdFrame_WithRetirePriorToEqualToSequencePromptsAllLowerRetirements()
    {
        QuicConnectionPeerConnectionIdState state = new();

        Assert.True(QuicConnectionIdLifecycleTestSupport.TryAcceptNewConnectionId(
            state,
            sequenceNumber: 1UL,
            retirePriorTo: 0UL,
            connectionIdStart: 0x40,
            activeConnectionIdLimit: 2UL,
            out QuicTransportErrorCode errorCode,
            out _,
            out _));
        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);

        Assert.True(QuicConnectionIdLifecycleTestSupport.TryAcceptNewConnectionId(
            state,
            sequenceNumber: 2UL,
            retirePriorTo: 2UL,
            connectionIdStart: 0x50,
            activeConnectionIdLimit: 2UL,
            out errorCode,
            out _,
            out ulong[] retiredSequenceNumbers));

        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        Assert.Equal([0UL, 1UL], retiredSequenceNumbers.Order().ToArray());
    }

}
