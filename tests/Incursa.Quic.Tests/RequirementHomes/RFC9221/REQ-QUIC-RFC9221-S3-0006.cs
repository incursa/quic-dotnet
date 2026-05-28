// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9221-S3-0006")]
public sealed class REQ_QUIC_RFC9221_S3_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ProtectedOneRttDatagramFrame_IsAcceptedWhenLocalSupportWasAdvertised()
    {
        using QuicConnectionRuntime runtime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
            localMaxDatagramFrameSize: 1200);

        QuicConnectionTransitionResult result = QuicDatagramRuntimeTestSupport.ReceiveProtectedDatagramFrame(
            runtime,
            new QuicDatagramFrame
            {
                FrameType = QuicFrameCodec.DatagramWithLengthFrameType,
                DatagramData = [0x51],
            });

        Assert.Single(result.Effects.OfType<QuicConnectionDeliverDatagramEffect>());
        Assert.Null(runtime.TerminalState);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9221-S3-0006")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ProtectedOneRttDatagramFrame_ClosesWhenLocalReceiveSupportWasNotAdvertised()
    {
        using QuicConnectionRuntime runtime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime();

        QuicConnectionTransitionResult result = QuicDatagramRuntimeTestSupport.ReceiveProtectedDatagramFrame(
            runtime,
            new QuicDatagramFrame
            {
                FrameType = QuicFrameCodec.DatagramWithLengthFrameType,
                DatagramData = [0x51],
            });

        Assert.True(result.StateChanged);
        QuicConnectionTerminalState terminalState = Assert.IsType<QuicConnectionTerminalState>(runtime.TerminalState);
        Assert.Equal(QuicTransportErrorCode.ProtocolViolation, terminalState.Close.TransportErrorCode);
        Assert.Equal(QuicFrameCodec.DatagramWithLengthFrameType, terminalState.Close.TriggeringFrameType);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionDeliverDatagramEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ProtectedOneRttEmptyDatagramFrame_IsAcceptedWhenLocalSupportAllowsFrameOverhead()
    {
        using QuicConnectionRuntime runtime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
            localMaxDatagramFrameSize: 2);

        QuicConnectionTransitionResult result = QuicDatagramRuntimeTestSupport.ReceiveProtectedDatagramFrame(
            runtime,
            new QuicDatagramFrame
            {
                FrameType = QuicFrameCodec.DatagramWithLengthFrameType,
                DatagramData = [],
            });

        Assert.Single(result.Effects.OfType<QuicConnectionDeliverDatagramEffect>());
        Assert.Null(runtime.TerminalState);
    }
}
