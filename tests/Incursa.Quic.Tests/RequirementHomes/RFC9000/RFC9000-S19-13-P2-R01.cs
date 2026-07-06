// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S19-13-P2-R01")]
public sealed class REQ_QUIC_RFC9000_1299
{
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="RFC9000-S19-13-P2-R01">An endpoint that receives a STREAM_DATA_BLOCKED frame for a send-only stream MUST terminate the connection with error STREAM_STATE_ERROR.</workbench-requirement>
    /// </workbench-requirements>
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ProtectedStreamDataBlockedFrame_ClosesWithStreamStateErrorForOpenedSendOnlyStream()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();

        Assert.True(runtime.StreamRegistry.Bookkeeping.TryOpenLocalStream(
            bidirectional: false,
            out QuicStreamId streamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        byte[] encoded = QuicFrameTestData.BuildStreamDataBlockedFrame(
            new QuicStreamDataBlockedFrame(streamId.Value, maximumStreamData: 4));

        QuicConnectionTransitionResult result = QuicS19P7NewTokenFrameTestSupport.ReceiveProtectedApplicationPacket(
            runtime,
            encoded,
            observedAtTicks: 20);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.NotNull(runtime.TerminalState);
        Assert.Equal(QuicConnectionCloseOrigin.Local, runtime.TerminalState!.Value.Origin);
        Assert.Equal(QuicTransportErrorCode.StreamStateError, runtime.TerminalState.Value.Close.TransportErrorCode);
        Assert.Equal(0x15UL, runtime.TerminalState.Value.Close.TriggeringFrameType);
        Assert.Contains(result.Effects, effect => effect is QuicConnectionSendDatagramEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReceiveStreamDataBlockedFrame_AcceptsReceiveCapableStreams()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 16,
            peerBidirectionalReceiveLimit: 8,
            peerBidirectionalStreamLimit: 8);

        Assert.True(state.TryReceiveStreamDataBlockedFrame(
            new QuicStreamDataBlockedFrame(streamId: 1, maximumStreamData: 4),
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamType.Bidirectional, snapshot.StreamType);
        Assert.Equal(QuicStreamSendState.Ready, snapshot.SendState);
        Assert.Equal(QuicStreamReceiveState.Recv, snapshot.ReceiveState);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReceiveStreamDataBlockedFrame_RejectsSendOnlyStreams()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState();

        Assert.True(state.TryOpenLocalStream(
            bidirectional: false,
            out QuicStreamId streamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.False(state.TryReceiveStreamDataBlockedFrame(
            new QuicStreamDataBlockedFrame(streamId.Value, 4),
            out QuicTransportErrorCode errorCode));
        Assert.Equal(QuicTransportErrorCode.StreamStateError, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamType.Unidirectional, snapshot.StreamType);
        Assert.Equal(QuicStreamSendState.Ready, snapshot.SendState);
        Assert.Equal(QuicStreamReceiveState.None, snapshot.ReceiveState);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ProtectedStreamDataBlockedFrame_ClosesWithStreamStateErrorForUncreatedSendOnlyStream()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        byte[] encoded = QuicFrameTestData.BuildStreamDataBlockedFrame(
            new QuicStreamDataBlockedFrame(streamId: 2, maximumStreamData: 0));

        QuicConnectionTransitionResult result = QuicS19P7NewTokenFrameTestSupport.ReceiveProtectedApplicationPacket(
            runtime,
            encoded,
            observedAtTicks: 20);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.NotNull(runtime.TerminalState);
        Assert.Equal(QuicConnectionCloseOrigin.Local, runtime.TerminalState!.Value.Origin);
        Assert.Equal(QuicTransportErrorCode.StreamStateError, runtime.TerminalState.Value.Close.TransportErrorCode);
        Assert.Equal(0x15UL, runtime.TerminalState.Value.Close.TriggeringFrameType);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TryReceiveStreamDataBlockedFrame_RejectsSendOnlyStreams()
    {
        foreach (ulong maximumStreamData in new[] { 0UL, 1UL, 4UL, 63UL, 16_383UL })
        {
            QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
                peerUnidirectionalStreamLimit: 8);

            Assert.True(state.TryOpenLocalStream(
                bidirectional: false,
                out QuicStreamId streamId,
                out QuicStreamsBlockedFrame blockedFrame));
            Assert.Equal(default, blockedFrame);

            Assert.False(state.TryReceiveStreamDataBlockedFrame(
                new QuicStreamDataBlockedFrame(streamId.Value, maximumStreamData),
                out QuicTransportErrorCode errorCode));

            Assert.Equal(QuicTransportErrorCode.StreamStateError, errorCode);
            Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshot));
            Assert.Equal(QuicStreamType.Unidirectional, snapshot.StreamType);
            Assert.Equal(QuicStreamSendState.Ready, snapshot.SendState);
            Assert.Equal(QuicStreamReceiveState.None, snapshot.ReceiveState);
        }
    }
}
