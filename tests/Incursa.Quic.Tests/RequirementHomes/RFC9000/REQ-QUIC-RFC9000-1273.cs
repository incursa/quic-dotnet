// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-1273")]
public sealed class REQ_QUIC_RFC9000_1273
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReceiveStreamFrame_AcceptsBytesAtTheAdvertisedConnectionLimit()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 4,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, streamId: 1, streamData: [0x10, 0x11], offset: 0),
            out QuicStreamFrame firstFrame));
        Assert.True(state.TryReceiveStreamFrame(firstFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, streamId: 5, streamData: [0x12, 0x13], offset: 0),
            out QuicStreamFrame secondFrame));
        Assert.True(state.TryReceiveStreamFrame(secondFrame, out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(4UL, state.ConnectionAccountedBytesReceived);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ProtectedStreamDataAboveAdvertisedMaxDataClosesWithFlowControlError()
    {
        using QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport.CreateConfirmedClientRuntimeWithValidatedActivePath(
                connectionReceiveLimit: 3,
                peerBidirectionalReceiveLimit: 8);

        QuicConnectionTransitionResult rejected = QuicStreamControlFrameTestSupport.ReceiveProtectedApplicationPayload(
            runtime,
            QuicStreamTestData.BuildStreamFrame(0x0E, streamId: 1, streamData: [0x10, 0x11, 0x12, 0x13], offset: 0),
            nowTicks: 20);

        QuicS19P9MaxDataFrameTestSupport.AssertLocalFlowControlClose(
            runtime,
            rejected,
            triggeringFrameType: 0x0E);
        Assert.Equal(0UL, runtime.StreamRegistry.Bookkeeping.ConnectionAccountedBytesReceived);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void TryReceiveStreamFrame_FuzzRejectsConnectionBytesAboveAdvertisedMaxData()
    {
        for (ulong connectionLimit = 1; connectionLimit <= 8; connectionLimit++)
        {
            QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
                connectionReceiveLimit: connectionLimit,
                peerBidirectionalReceiveLimit: 32);
            byte[] data = Enumerable.Range(0, (int)connectionLimit + 1)
                .Select(value => (byte)(0x30 + value))
                .ToArray();

            Assert.True(QuicStreamParser.TryParseStreamFrame(
                QuicStreamTestData.BuildStreamFrame(0x0E, streamId: 1, streamData: data, offset: 0),
                out QuicStreamFrame frame));

            Assert.False(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
            Assert.Equal(QuicTransportErrorCode.FlowControlError, errorCode);
            Assert.Equal(0UL, state.ConnectionAccountedBytesReceived);
        }
    }
}
