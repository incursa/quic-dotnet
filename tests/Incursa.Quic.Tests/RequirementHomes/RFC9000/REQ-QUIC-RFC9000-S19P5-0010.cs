// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P5-0010")]
public sealed class REQ_QUIC_RFC9000_S19P5_0010
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0010")]
    [Requirement("REQ-QUIC-RFC9000-S20P2-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task AbortRead_EncodesApplicationErrorReason()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        List<QuicConnectionEffect> outboundEffects = [];

        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        outboundEffects.Clear();

        stream.Abort(QuicAbortDirection.Read, 0x66);

        Assert.True(QuicStreamControlFrameTestSupport.TryFindProtectedStopSendingFrame(
            runtime,
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>(),
            out QuicStopSendingFrame stopSendingFrame));
        Assert.Equal(0x66UL, stopSendingFrame.ApplicationProtocolErrorCode);

        await stream.DisposeAsync();
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0010")]
    [Requirement("REQ-QUIC-RFC9000-S20P2-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReceiveStopSendingFrame_DoesNotForwardRejectedApplicationErrorReason()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState();

        Assert.False(state.TryReceiveStopSendingFrame(
            new QuicStopSendingFrame(streamId: 3, applicationProtocolErrorCode: 0x77),
            out QuicResetStreamFrame resetStreamFrame,
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, resetStreamFrame);
        Assert.Equal(QuicTransportErrorCode.StreamStateError, errorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0010")]
    [Requirement("REQ-QUIC-RFC9000-S20P2-0001")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryReceiveStopSendingFrame_ForwardsMaximumApplicationErrorReason()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState();

        Assert.True(state.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.True(state.TryReceiveStopSendingFrame(
            new QuicStopSendingFrame(
                streamId.Value,
                applicationProtocolErrorCode: QuicVariableLengthInteger.MaxValue),
            out QuicResetStreamFrame resetStreamFrame,
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(QuicVariableLengthInteger.MaxValue, resetStreamFrame.ApplicationProtocolErrorCode);
    }
}
