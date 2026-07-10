// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P12-0002">DATA_BLOCKED frames MAY be used as input to tuning of flow control algorithms; see Section 4.2.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S19P12-0002")]
public sealed class REQ_QUIC_RFC9000_S19P12_0002
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P12-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ProtectedDataBlockedFrame_ReplaysNewerConnectionCredit()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        ulong currentReceiveLimit = runtime.StreamRegistry.Bookkeeping.ConnectionReceiveLimit;
        byte[] encoded = QuicS19P12DataBlockedFrameTestSupport.BuildDataBlockedFrame(currentReceiveLimit - 1);

        QuicConnectionTransitionResult result = QuicS19P7NewTokenFrameTestSupport.ReceiveProtectedApplicationPacket(
            runtime,
            encoded,
            observedAtTicks: 20);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.Null(runtime.TerminalState);
        Assert.Contains(
            result.Effects.OfType<QuicConnectionSendDatagramEffect>(),
            effect => ContainsMaxDataFrame(
                QuicS13AckPiggybackTestSupport.OpenOutgoingApplicationPayload(runtime, effect),
                currentReceiveLimit));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P12-0002")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ProtectedDataBlockedFrame_DoesNotReplayCurrentConnectionCredit()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        ulong currentReceiveLimit = runtime.StreamRegistry.Bookkeeping.ConnectionReceiveLimit;
        byte[] encoded = QuicS19P12DataBlockedFrameTestSupport.BuildDataBlockedFrame(currentReceiveLimit);

        QuicConnectionTransitionResult result = QuicS19P7NewTokenFrameTestSupport.ReceiveProtectedApplicationPacket(
            runtime,
            encoded,
            observedAtTicks: 20);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.Null(runtime.TerminalState);
        Assert.DoesNotContain(
            result.Effects.OfType<QuicConnectionSendDatagramEffect>(),
            effect => ContainsMaxDataFrame(
                QuicS13AckPiggybackTestSupport.OpenOutgoingApplicationPayload(runtime, effect),
                currentReceiveLimit));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P12-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReserveSendCapacity_ExposesTheCurrentConnectionLimitAsFlowControlTuningInput()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionSendLimit: 1,
            localBidirectionalSendLimit: 8);

        Assert.True(state.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.False(state.TryReserveSendCapacity(
            streamId.Value,
            offset: 0,
            length: 2,
            fin: false,
            out QuicDataBlockedFrame dataBlockedFrame,
            out QuicStreamDataBlockedFrame streamDataBlockedFrame,
            out QuicTransportErrorCode errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(1UL, dataBlockedFrame.MaximumData);
        Assert.Equal(default, streamDataBlockedFrame);

        Assert.True(state.TryApplyMaxDataFrame(new QuicMaxDataFrame(2)));
        Assert.Equal(2UL, state.ConnectionSendLimit);

        Assert.True(state.TryReserveSendCapacity(
            streamId.Value,
            offset: 0,
            length: 1,
            fin: false,
            out dataBlockedFrame,
            out streamDataBlockedFrame,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(default, dataBlockedFrame);
        Assert.Equal(default, streamDataBlockedFrame);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P12-0002")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReserveSendCapacity_DoesNotNeedToEmitDataBlockedFramesWhenConnectionCreditRemains()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionSendLimit: 8,
            localBidirectionalSendLimit: 8);

        Assert.True(state.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.True(state.TryReserveSendCapacity(
            streamId.Value,
            offset: 0,
            length: 2,
            fin: false,
            out QuicDataBlockedFrame dataBlockedFrame,
            out QuicStreamDataBlockedFrame streamDataBlockedFrame,
            out QuicTransportErrorCode errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(default, dataBlockedFrame);
        Assert.Equal(default, streamDataBlockedFrame);
    }

    private static bool ContainsMaxDataFrame(ReadOnlySpan<byte> payload, ulong expectedMaximumData)
    {
        while (!payload.IsEmpty)
        {
            if (QuicFrameCodec.TryParseMaxDataFrame(payload, out QuicMaxDataFrame frame, out int bytesConsumed))
            {
                return frame.MaximumData == expectedMaximumData;
            }

            if (QuicFrameCodec.TryParseAckFrame(payload, out QuicAckFrame ackFrame, out bytesConsumed))
            {
                ackFrame.Dispose();
                payload = payload[bytesConsumed..];
                continue;
            }

            if (QuicFrameCodec.TryParsePaddingFrame(payload, out bytesConsumed))
            {
                payload = payload[bytesConsumed..];
                continue;
            }

            return false;
        }

        return false;
    }
}
