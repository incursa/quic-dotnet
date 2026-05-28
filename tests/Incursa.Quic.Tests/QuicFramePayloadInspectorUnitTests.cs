// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class QuicFramePayloadInspectorUnitTests
{
    [Fact]
    public void ContainsStopSendingFrameForStream_MatchesTheTargetStreamAndIgnoresOtherStreams()
    {
        ulong targetStreamId = 0x04;
        ulong otherStreamId = 0x06;
        byte[] payload =
        [
            ..QuicFrameTestData.BuildPaddingFrame(),
            ..BuildMinimalAckFrame(),
            ..QuicFrameTestData.BuildStopSendingFrame(new QuicStopSendingFrame(otherStreamId, 0x11)),
            ..QuicFrameTestData.BuildStopSendingFrame(new QuicStopSendingFrame(targetStreamId, 0x22)),
        ];

        Assert.True(QuicFramePayloadInspector.ContainsStopSendingFrameForStream(payload, targetStreamId));
        Assert.False(QuicFramePayloadInspector.ContainsStopSendingFrameForStream(payload, 0x08));
    }

    [Fact]
    public void GetStreamDataStreamIds_IgnoresZeroLengthStreamFrames()
    {
        byte[] payload =
        [
            ..QuicStreamTestData.BuildStreamFrame(0x0A, 0x01, []),
            ..QuicFrameTestData.BuildPaddingFrame(),
            ..BuildMinimalAckFrame(),
            ..QuicFrameTestData.BuildPingFrame(),
            ..QuicStreamTestData.BuildStreamFrame(0x0A, 0x02, []),
        ];

        Assert.Empty(QuicFramePayloadInspector.GetStreamDataStreamIds(payload));
    }

    [Fact]
    public void GetStreamDataStreamIds_ReturnsDistinctStreamIdsAndTruncatesMalformedPayloads()
    {
        byte[] payload =
        [
            ..QuicFrameTestData.BuildPaddingFrame(),
            ..BuildMinimalAckFrame(),
            ..QuicFrameTestData.BuildPingFrame(),
            ..QuicStreamTestData.BuildStreamFrame(0x0A, 0x01, []),
            ..QuicStreamTestData.BuildStreamFrame(0x0A, 0x01, [0x11]),
            ..QuicStreamTestData.BuildStreamFrame(0x0A, 0x01, [0x12]),
            ..QuicStreamTestData.BuildStreamFrame(0x0A, 0x02, [0x21, 0x22]),
            ..QuicFrameTestData.BuildStopSendingFrame(new QuicStopSendingFrame(0x03, 0x33)),
            ..QuicFrameTestData.BuildResetStreamFrame(new QuicResetStreamFrame(0x04, 0x44, 0x00)),
            0xFF,
            ..QuicStreamTestData.BuildStreamFrame(0x0A, 0x03, [0x31]),
        ];

        ulong[] expectedStreamIds = [0x01UL, 0x02UL];

        Assert.Equal(expectedStreamIds, QuicFramePayloadInspector.GetStreamDataStreamIds(payload));
    }

    [Fact]
    public void ContainsStreamDataForStream_IgnoresZeroLengthFramesAndSkipsSupportedFrames()
    {
        ulong targetStreamId = 0x0A;
        byte[] zeroLengthPayload = QuicStreamTestData.BuildStreamFrame(0x0A, targetStreamId, []);
        byte[] payload =
        [
            ..QuicFrameTestData.BuildPaddingFrame(),
            ..BuildMinimalAckFrame(),
            ..QuicFrameTestData.BuildPingFrame(),
            ..zeroLengthPayload,
            ..QuicFrameTestData.BuildStopSendingFrame(new QuicStopSendingFrame(0x0B, 0x55)),
            ..QuicFrameTestData.BuildResetStreamFrame(new QuicResetStreamFrame(0x0C, 0x66, 0x00)),
            ..QuicStreamTestData.BuildStreamFrame(0x0A, targetStreamId, [0xAA]),
        ];

        Assert.False(QuicFramePayloadInspector.ContainsStreamDataForStream(zeroLengthPayload, targetStreamId));
        Assert.True(QuicFramePayloadInspector.ContainsStreamDataForStream(payload, targetStreamId));
        Assert.False(QuicFramePayloadInspector.ContainsStreamDataForStream(payload, 0x0D));
    }

    [Fact]
    public void ContainsResetStreamFrameForStream_MatchesTheTargetStreamAndSkipsSupportedFrames()
    {
        ulong targetStreamId = 0x07;
        byte[] payload =
        [
            ..QuicFrameTestData.BuildPaddingFrame(),
            ..BuildMinimalAckFrame(),
            ..QuicFrameTestData.BuildPingFrame(),
            ..QuicFrameTestData.BuildResetStreamFrame(new QuicResetStreamFrame(0x08, 0x11, 0x00)),
            ..QuicFrameTestData.BuildStopSendingFrame(new QuicStopSendingFrame(0x09, 0x22)),
            ..QuicFrameTestData.BuildResetStreamFrame(new QuicResetStreamFrame(targetStreamId, 0x33, 0x44)),
        ];

        Assert.True(QuicFramePayloadInspector.ContainsResetStreamFrameForStream(payload, targetStreamId));
        Assert.False(QuicFramePayloadInspector.ContainsResetStreamFrameForStream(payload, 0x0A));
    }

    private static byte[] BuildMinimalAckFrame()
    {
        return QuicFrameTestData.BuildAckFrame(new QuicAckFrame
        {
            FrameType = 0x02,
            LargestAcknowledged = 0,
            AckDelay = 0,
            FirstAckRange = 0,
        });
    }
}
