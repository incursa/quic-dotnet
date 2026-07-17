// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class QuicStreamReceiveBufferTests
{
    [Fact]
    public void RuntimeReceiveResultCombinesReadinessCompletionAndFirstAcceptDecision()
    {
        QuicConnectionStreamState state = CreateServerReceiveState();
        QuicStreamFrame firstFrame = ParseStreamFrame(streamId: 0, offset: 0, [0x11], fin: false);

        Assert.True(state.TryReceiveStreamFrameForRuntime(
            firstFrame,
            out QuicTransportErrorCode errorCode,
            out QuicConnectionStreamReceiveResult firstResult));
        Assert.Equal(default, errorCode);
        Assert.True(firstResult.HasReadableData);
        Assert.False(firstResult.ReceiveCompleted);
        Assert.True(firstResult.QueuePeerAccept);

        Assert.True(state.TryReceiveStreamFrameForRuntime(
            ParseStreamFrame(streamId: 0, offset: 1, [0x22], fin: true),
            out errorCode,
            out QuicConnectionStreamReceiveResult terminalResult));
        Assert.Equal(default, errorCode);
        Assert.True(terminalResult.HasReadableData);
        Assert.True(terminalResult.ReceiveCompleted);
        Assert.False(terminalResult.QueuePeerAccept);
    }

    [Fact]
    public void LegacyReceiveEntryPointDoesNotConsumeRuntimeAcceptDecision()
    {
        QuicConnectionStreamState state = CreateServerReceiveState();
        QuicStreamFrame frame = ParseStreamFrame(streamId: 0, offset: 0, [0x11], fin: true);

        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.True(state.TryMarkPeerAcceptQueued(0));
        Assert.False(state.TryMarkPeerAcceptQueued(0));
    }

    [Fact]
    [Requirement("REQ-QUIC-CRT-0155")]
    public void ReceiveRetentionSnapshotTracksBufferCapacityAndUnreadBytes()
    {
        QuicConnectionStreamState state = CreateServerReceiveState();
        byte[] payload = Enumerable.Repeat((byte)0x5A, 1024).ToArray();

        Assert.True(state.TryReceiveStreamFrame(
            ParseStreamFrame(streamId: 0, offset: 0, payload, fin: true),
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        QuicReceiveRetentionSnapshot initial = state.CaptureReceiveRetentionSnapshot();
        Assert.Equal(1, initial.RetainedBufferCount);
        Assert.Equal(1024, initial.RetainedBufferBytes);
        Assert.Equal(payload.Length, initial.BufferedBytes);
        Assert.Equal(1, initial.BufferedStreamCount);

        byte[] firstRead = new byte[512];
        Assert.True(state.TryReadStreamData(0, firstRead, out int bytesWritten, out _, out _, out _, out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(firstRead.Length, bytesWritten);

        QuicReceiveRetentionSnapshot partial = state.CaptureReceiveRetentionSnapshot();
        Assert.Equal(1, partial.RetainedBufferCount);
        Assert.Equal(1024, partial.RetainedBufferBytes);
        Assert.Equal(payload.Length - firstRead.Length, partial.BufferedBytes);
        Assert.Equal(1, partial.BufferedStreamCount);

        byte[] secondRead = new byte[payload.Length - firstRead.Length];
        Assert.True(state.TryReadStreamData(0, secondRead, out bytesWritten, out bool completed, out _, out _, out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(secondRead.Length, bytesWritten);
        Assert.True(completed);
        Assert.Equal(default, state.CaptureReceiveRetentionSnapshot());
    }

    [Fact]
    [Requirement("REQ-QUIC-CRT-0155")]
    public void NonTerminalReceiveSegmentRetainsCoalescingCapacity()
    {
        QuicConnectionStreamState state = CreateServerReceiveState();
        byte[] payload = Enumerable.Repeat((byte)0x4A, 1024).ToArray();

        Assert.True(state.TryReceiveStreamFrame(
            ParseStreamFrame(streamId: 0, offset: 0, payload, fin: false),
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(
            new QuicReceiveRetentionSnapshot(1, 4 * 1024, payload.Length, 1),
            state.CaptureReceiveRetentionSnapshot());
    }

    [Fact]
    [Requirement("REQ-QUIC-CRT-0155")]
    public void TerminalTailDoesNotReserveUnusedContinuationCapacity()
    {
        QuicConnectionStreamState state = CreateServerReceiveState(receiveLimit: 8 * 1024);
        byte[] first = Enumerable.Repeat((byte)0x31, 4 * 1024).ToArray();
        byte[] tail = Enumerable.Repeat((byte)0x32, 1024).ToArray();

        Assert.True(state.TryReceiveStreamFrame(
            ParseStreamFrame(streamId: 0, offset: 0, first, fin: false),
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.True(state.TryReceiveStreamFrame(
            ParseStreamFrame(streamId: 0, offset: (ulong)first.Length, tail, fin: true),
            out errorCode));
        Assert.Equal(default, errorCode);

        Assert.Equal(
            new QuicReceiveRetentionSnapshot(
                RetainedBufferCount: 2,
                RetainedBufferBytes: first.Length + tail.Length,
                BufferedBytes: first.Length + tail.Length,
                BufferedStreamCount: 1),
            state.CaptureReceiveRetentionSnapshot());
    }

    [Fact]
    [Requirement("REQ-QUIC-CRT-0155")]
    public void KnownFinalSizeMakesReorderedTerminalDataUseExactCapacity()
    {
        QuicConnectionStreamState state = CreateServerReceiveState();
        byte[] payload = Enumerable.Repeat((byte)0x42, 1024).ToArray();

        Assert.True(state.TryReceiveStreamFrame(
            ParseStreamFrame(streamId: 0, offset: (ulong)payload.Length, [], fin: true),
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.True(state.TryReceiveStreamFrame(
            ParseStreamFrame(streamId: 0, offset: 0, payload, fin: false),
            out errorCode));
        Assert.Equal(default, errorCode);

        Assert.Equal(
            new QuicReceiveRetentionSnapshot(1, payload.Length, payload.Length, 1),
            state.CaptureReceiveRetentionSnapshot());

        byte[] destination = new byte[payload.Length];
        Assert.True(state.TryReadStreamData(
            streamIdValue: 0,
            destination,
            out int bytesWritten,
            out bool completed,
            out _,
            out _,
            out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(payload.Length, bytesWritten);
        Assert.True(completed);
        Assert.Equal(payload, destination);
        Assert.Equal(default, state.CaptureReceiveRetentionSnapshot());
    }

    [Fact]
    [Requirement("REQ-QUIC-CRT-0155")]
    public void ReceiveRetentionSnapshotUsesLargerContinuationBlocksForSustainedFrames()
    {
        const int payloadLength = 64 * 1024;
        const int framePayloadLength = 1152;
        QuicConnectionStreamState state = CreateServerReceiveState(receiveLimit: 128 * 1024);
        byte[] payload = Enumerable.Repeat((byte)0x6A, payloadLength).ToArray();

        for (int offset = 0; offset < payload.Length; offset += framePayloadLength)
        {
            int length = Math.Min(framePayloadLength, payload.Length - offset);
            Assert.True(state.TryReceiveStreamFrame(
                ParseStreamFrame(
                    streamId: 0,
                    offset: (ulong)offset,
                    payload.AsSpan(offset, length),
                    fin: offset + length == payload.Length),
                out QuicTransportErrorCode errorCode));
            Assert.Equal(default, errorCode);
        }

        Assert.Equal(
            new QuicReceiveRetentionSnapshot(
                RetainedBufferCount: 9,
                RetainedBufferBytes: 68 * 1024,
                BufferedBytes: payloadLength,
                BufferedStreamCount: 1),
            state.CaptureReceiveRetentionSnapshot());

        byte[] destination = new byte[payload.Length];
        Assert.True(state.TryReadStreamData(
            0,
            destination,
            out int bytesWritten,
            out bool completed,
            out _,
            out _,
            out QuicTransportErrorCode readErrorCode));
        Assert.Equal(default, readErrorCode);
        Assert.Equal(payload.Length, bytesWritten);
        Assert.True(completed);
        Assert.Equal(payload, destination);
        Assert.Equal(default, state.CaptureReceiveRetentionSnapshot());
    }

    [Fact]
    [Requirement("REQ-QUIC-CRT-0155")]
    public void ReceiveRetentionSnapshotTracksMultipleStreamsWithoutDoubleCountingDuplicates()
    {
        QuicConnectionStreamState state = CreateServerReceiveState();
        byte[] firstPayload = Enumerable.Repeat((byte)0x11, 1024).ToArray();
        byte[] secondPayload = Enumerable.Repeat((byte)0x22, 1024).ToArray();

        Assert.True(state.TryReceiveStreamFrame(
            ParseStreamFrame(streamId: 0, offset: 0, firstPayload, fin: false),
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.True(state.TryReceiveStreamFrame(
            ParseStreamFrame(streamId: 4, offset: 0, secondPayload, fin: false),
            out errorCode));
        Assert.Equal(default, errorCode);
        Assert.True(state.TryReceiveStreamFrame(
            ParseStreamFrame(streamId: 0, offset: 0, firstPayload, fin: false),
            out errorCode));
        Assert.Equal(default, errorCode);

        Assert.Equal(
            new QuicReceiveRetentionSnapshot(2, 8 * 1024, 2 * 1024, 2),
            state.CaptureReceiveRetentionSnapshot());

        Assert.True(state.TryReceiveResetStreamFrame(
            new QuicResetStreamFrame(streamId: 0, applicationProtocolErrorCode: 42, finalSize: (ulong)firstPayload.Length),
            out _,
            out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(
            new QuicReceiveRetentionSnapshot(1, 4 * 1024, secondPayload.Length, 1),
            state.CaptureReceiveRetentionSnapshot());

        byte[] destination = new byte[secondPayload.Length];
        Assert.True(state.TryReadStreamData(4, destination, out int bytesWritten, out _, out _, out _, out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(destination.Length, bytesWritten);
        Assert.Equal(secondPayload, destination);
        Assert.Equal(default, state.CaptureReceiveRetentionSnapshot());
    }

    [Fact]
    [Requirement("REQ-QUIC-CRT-0155")]
    public void ReceiveRetentionSnapshotKeepsSparseBlocksSmallAndClearsPartiallyReadSpillOnReset()
    {
        QuicConnectionStreamState state = CreateServerReceiveState();
        byte[] payload = Enumerable.Repeat((byte)0x33, 1024).ToArray();

        foreach (ulong offset in new ulong[] { 0, 1536, 3072 })
        {
            Assert.True(state.TryReceiveStreamFrame(
                ParseStreamFrame(streamId: 0, offset, payload, fin: false),
                out QuicTransportErrorCode receiveErrorCode));
            Assert.Equal(default, receiveErrorCode);
        }

        byte[] partialRead = new byte[512];
        Assert.True(state.TryReadStreamData(0, partialRead, out int bytesWritten, out _, out _, out _, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(partialRead.Length, bytesWritten);
        Assert.Equal(
            new QuicReceiveRetentionSnapshot(3, 12 * 1024, (3 * payload.Length) - partialRead.Length, 1),
            state.CaptureReceiveRetentionSnapshot());

        Assert.True(state.TryReceiveResetStreamFrame(
            new QuicResetStreamFrame(streamId: 0, applicationProtocolErrorCode: 42, finalSize: 4096),
            out _,
            out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(default, state.CaptureReceiveRetentionSnapshot());
    }

    [Fact]
    public void TryReceiveStreamFrame_ReadsSinglePayloadBytesExactly()
    {
        QuicConnectionStreamState state = CreateServerReceiveState();
        byte[] payload = [0x48, 0x45, 0x41, 0x44, 0x45, 0x52, 0x53];
        QuicStreamFrame frame = ParseStreamFrame(streamId: 0, offset: 0, payload, fin: false);

        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        byte[] destination = new byte[payload.Length];
        Assert.True(state.TryReadStreamData(
            frame.StreamId.Value,
            destination,
            out int bytesWritten,
            out bool completed,
            out _,
            out _,
            out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(payload.Length, bytesWritten);
        Assert.False(completed);
        Assert.True(payload.AsSpan().SequenceEqual(destination));
    }

    [Fact]
    public void TryReceiveStreamFrame_ReadsContiguousFramesInOrder()
    {
        QuicConnectionStreamState state = CreateServerReceiveState();
        byte[] first = [0x48, 0x45, 0x41, 0x44];
        byte[] second = [0x45, 0x52, 0x53];

        Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(streamId: 0, offset: 0, first, fin: false), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(streamId: 0, offset: (ulong)first.Length, second, fin: false), out errorCode));
        Assert.Equal(default, errorCode);

        byte[] destination = new byte[first.Length + second.Length];
        Assert.True(state.TryReadStreamData(
            streamIdValue: 0,
            destination,
            out int bytesWritten,
            out bool completed,
            out _,
            out _,
            out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(destination.Length, bytesWritten);
        Assert.False(completed);
        Assert.True(((ReadOnlySpan<byte>)[0x48, 0x45, 0x41, 0x44, 0x45, 0x52, 0x53]).SequenceEqual(destination));
    }

    [Fact]
    public void TryReceiveStreamFrame_ReadsThreeContiguousFramesAcrossInlineAndListStorage()
    {
        QuicConnectionStreamState state = CreateServerReceiveState();
        byte[][] payloads = [[0x10, 0x11], [0x20, 0x21], [0x30, 0x31]];

        ulong offset = 0;
        foreach (byte[] payload in payloads)
        {
            Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(streamId: 0, offset, payload, fin: false), out QuicTransportErrorCode errorCode));
            Assert.Equal(default, errorCode);
            offset += (ulong)payload.Length;
        }

        foreach (byte[] expected in payloads)
        {
            byte[] destination = new byte[expected.Length];
            Assert.True(state.TryReadStreamData(
                streamIdValue: 0,
                destination,
                out int bytesWritten,
                out bool completed,
                out _,
                out _,
                out QuicTransportErrorCode errorCode));
            Assert.Equal(default, errorCode);
            Assert.Equal(expected.Length, bytesWritten);
            Assert.False(completed);
            Assert.Equal(expected, destination);
        }
    }

    [Fact]
    public void TryReceiveStreamFrame_PreservesUnreadTailAfterPartialRead()
    {
        QuicConnectionStreamState state = CreateServerReceiveState();
        byte[] payload = [0x10, 0x11, 0x12, 0x13, 0x14];

        Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(streamId: 0, offset: 0, payload, fin: true), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        byte[] firstRead = new byte[2];
        Assert.True(state.TryReadStreamData(0, firstRead, out int firstBytesWritten, out bool firstCompleted, out _, out _, out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(2, firstBytesWritten);
        Assert.False(firstCompleted);
        Assert.True(((ReadOnlySpan<byte>)[0x10, 0x11]).SequenceEqual(firstRead));

        byte[] secondRead = new byte[3];
        Assert.True(state.TryReadStreamData(0, secondRead, out int secondBytesWritten, out bool secondCompleted, out _, out _, out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(3, secondBytesWritten);
        Assert.True(secondCompleted);
        Assert.True(((ReadOnlySpan<byte>)[0x12, 0x13, 0x14]).SequenceEqual(secondRead));
    }

    [Fact]
    public void TryReceiveStreamFrame_AppendsContiguousBytesAfterPartialRead()
    {
        QuicConnectionStreamState state = CreateServerReceiveState();
        byte[] firstPayload = Enumerable.Repeat((byte)0x10, 1024).ToArray();
        byte[] secondPayload = Enumerable.Repeat((byte)0x20, 1024).ToArray();

        Assert.True(state.TryReceiveStreamFrame(
            ParseStreamFrame(streamId: 0, offset: 0, firstPayload, fin: false),
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        byte[] firstRead = new byte[256];
        Assert.True(state.TryReadStreamData(0, firstRead, out int firstBytesWritten, out bool firstCompleted, out _, out _, out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(firstRead.Length, firstBytesWritten);
        Assert.False(firstCompleted);
        Assert.Equal(firstPayload.AsSpan(0, firstRead.Length).ToArray(), firstRead);

        Assert.True(state.TryReceiveStreamFrame(
            ParseStreamFrame(streamId: 0, offset: (ulong)firstPayload.Length, secondPayload, fin: true),
            out errorCode));
        Assert.Equal(default, errorCode);

        byte[] secondRead = new byte[firstPayload.Length - firstRead.Length + secondPayload.Length];
        Assert.True(state.TryReadStreamData(0, secondRead, out int secondBytesWritten, out bool secondCompleted, out _, out _, out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(secondRead.Length, secondBytesWritten);
        Assert.True(secondCompleted);
        Assert.Equal(firstPayload.AsSpan(firstRead.Length).ToArray(), secondRead.AsSpan(0, firstPayload.Length - firstRead.Length).ToArray());
        Assert.Equal(secondPayload, secondRead.AsSpan(firstPayload.Length - firstRead.Length).ToArray());
    }

    [Fact]
    public void TryReceiveStreamFrame_PreservesFirstPayloadForConflictingDuplicate()
    {
        QuicConnectionStreamState state = CreateServerReceiveState();

        Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(streamId: 0, offset: 0, [0x11, 0x22, 0x33], fin: false), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(streamId: 0, offset: 0, [0xAA, 0xBB, 0xCC], fin: false), out errorCode));
        Assert.Equal(default, errorCode);

        byte[] destination = new byte[3];
        Assert.True(state.TryReadStreamData(0, destination, out int bytesWritten, out bool completed, out _, out _, out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(3, bytesWritten);
        Assert.False(completed);
        Assert.True(((ReadOnlySpan<byte>)[0x11, 0x22, 0x33]).SequenceEqual(destination));
    }

    [Fact]
    public void TryReceiveStreamFrame_DuplicateAfterPartialReadDoesNotReplaceUnreadTail()
    {
        QuicConnectionStreamState state = CreateServerReceiveState();

        Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(streamId: 0, offset: 0, [0x11, 0x22, 0x33], fin: true), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        byte[] firstRead = new byte[2];
        Assert.True(state.TryReadStreamData(0, firstRead, out int firstBytesWritten, out bool firstCompleted, out _, out _, out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(2, firstBytesWritten);
        Assert.False(firstCompleted);
        Assert.True(((ReadOnlySpan<byte>)[0x11, 0x22]).SequenceEqual(firstRead));

        Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(streamId: 0, offset: 0, [0xAA, 0xBB, 0xCC], fin: true), out errorCode));
        Assert.Equal(default, errorCode);

        byte[] secondRead = new byte[1];
        Assert.True(state.TryReadStreamData(0, secondRead, out int secondBytesWritten, out bool secondCompleted, out _, out _, out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(1, secondBytesWritten);
        Assert.True(secondCompleted);
        Assert.Equal(0x33, secondRead[0]);
    }

    [Fact]
    public void TryReceiveStreamFrame_OverlappingFrameAddsOnlyMissingTail()
    {
        QuicConnectionStreamState state = CreateServerReceiveState();

        Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(streamId: 0, offset: 0, [0x11, 0x22, 0x33], fin: false), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(streamId: 0, offset: 1, [0xAA, 0xBB, 0x44, 0x55], fin: true), out errorCode));
        Assert.Equal(default, errorCode);

        byte[] destination = new byte[5];
        Assert.True(state.TryReadStreamData(0, destination, out int bytesWritten, out bool completed, out _, out _, out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(5, bytesWritten);
        Assert.True(completed);
        Assert.True(((ReadOnlySpan<byte>)[0x11, 0x22, 0x33, 0x44, 0x55]).SequenceEqual(destination));
    }

    [Fact]
    public void TryReceiveStreamFrame_FillsManyHolesWithoutDoubleCountingBufferedBytes()
    {
        const int segmentLength = 4;
        const int segmentCount = 8;
        const int totalLength = ((segmentCount * 2) + 1) * segmentLength;
        QuicConnectionStreamState state = CreateServerReceiveState();
        byte[] expected = new byte[totalLength];

        for (int index = 0; index < segmentCount; index++)
        {
            byte[] payload = Enumerable.Repeat((byte)(0x80 + index), segmentLength).ToArray();
            int offset = ((index * 2) + 1) * segmentLength;
            payload.CopyTo(expected, offset);
            Assert.True(state.TryReceiveStreamFrame(
                ParseStreamFrame(streamId: 0, (ulong)offset, payload, fin: false),
                out QuicTransportErrorCode errorCode));
            Assert.Equal(default, errorCode);
        }

        byte[] fillingPayload = Enumerable.Repeat((byte)0x20, totalLength).ToArray();
        for (int offset = 0; offset < totalLength; offset += segmentLength * 2)
        {
            fillingPayload.AsSpan(offset, Math.Min(segmentLength, totalLength - offset))
                .CopyTo(expected.AsSpan(offset));
        }

        Assert.True(state.TryReceiveStreamFrame(
            ParseStreamFrame(streamId: 0, offset: 0, fillingPayload, fin: true),
            out QuicTransportErrorCode fillErrorCode));
        Assert.Equal(default, fillErrorCode);
        Assert.True(state.TryGetStreamSnapshot(0, out QuicConnectionStreamSnapshot beforeRead));
        Assert.Equal((ulong)totalLength, beforeRead.UniqueBytesReceived);
        Assert.Equal(totalLength, beforeRead.BufferedReadableBytes);

        byte[] destination = new byte[totalLength];
        Assert.True(state.TryReadStreamData(
            0,
            destination,
            out int bytesWritten,
            out bool completed,
            out _,
            out _,
            out QuicTransportErrorCode readErrorCode));
        Assert.Equal(default, readErrorCode);
        Assert.Equal(totalLength, bytesWritten);
        Assert.True(completed);
        Assert.Equal(expected, destination);
        Assert.True(state.TryGetStreamSnapshot(0, out QuicConnectionStreamSnapshot afterRead));
        Assert.Equal(0, afterRead.BufferedReadableBytes);
    }

    [Fact]
    public void TryReceiveStreamFrame_PreservesDataAcrossRepeatedHoleFillingMerges()
    {
        QuicConnectionStreamState state = CreateServerReceiveState();
        byte[] expected = Enumerable.Repeat((byte)0x20, 36).ToArray();

        for (int offset = 4; offset < expected.Length; offset += 8)
        {
            byte[] payload = Enumerable.Repeat((byte)(0x80 + offset), 4).ToArray();
            payload.CopyTo(expected, offset);
            Assert.True(state.TryReceiveStreamFrame(
                ParseStreamFrame(streamId: 0, (ulong)offset, payload, fin: false),
                out QuicTransportErrorCode seedErrorCode));
            Assert.Equal(default, seedErrorCode);
        }

        for (int offset = 0; offset < expected.Length; offset += 8)
        {
            int length = Math.Min(8, expected.Length - offset);
            byte[] payload = Enumerable.Repeat((byte)0x20, length).ToArray();
            Assert.True(state.TryReceiveStreamFrame(
                ParseStreamFrame(streamId: 0, (ulong)offset, payload, fin: offset + length == expected.Length),
                out QuicTransportErrorCode fillErrorCode));
            Assert.Equal(default, fillErrorCode);
        }

        Assert.True(state.TryGetStreamSnapshot(0, out QuicConnectionStreamSnapshot beforeRead));
        Assert.Equal((ulong)expected.Length, beforeRead.UniqueBytesReceived);
        Assert.Equal(expected.Length, beforeRead.BufferedReadableBytes);

        byte[] destination = new byte[expected.Length];
        Assert.True(state.TryReadStreamData(
            0,
            destination,
            out int bytesWritten,
            out bool completed,
            out _,
            out _,
            out QuicTransportErrorCode readErrorCode));
        Assert.Equal(default, readErrorCode);
        Assert.Equal(expected.Length, bytesWritten);
        Assert.True(completed);
        Assert.Equal(expected, destination);
    }

    [Fact]
    public void TerminalInterleavedStreamsPreserveDataAcrossConcurrentWorkers()
    {
        const int segmentLength = 4;
        const int segmentCount = 8;
        const int totalLength = ((segmentCount * 2) + 1) * segmentLength;

        Parallel.For(0, 32, workerIndex =>
        {
            QuicConnectionStreamState state = CreateServerReceiveState();
            byte[] expected = Enumerable.Repeat((byte)0x20, totalLength).ToArray();

            for (int index = 0; index < segmentCount; index++)
            {
                byte[] payload = Enumerable.Repeat((byte)(0x80 + index + workerIndex), segmentLength).ToArray();
                int offset = ((index * 2) + 1) * segmentLength;
                payload.CopyTo(expected, offset);
                Assert.True(state.TryReceiveStreamFrame(
                    ParseStreamFrame(streamId: 0, (ulong)offset, payload, fin: false),
                    out QuicTransportErrorCode seedErrorCode));
                Assert.Equal(default, seedErrorCode);
            }

            byte[] fillingPayload = Enumerable.Repeat((byte)0x20, totalLength).ToArray();
            Assert.True(state.TryReceiveStreamFrame(
                ParseStreamFrame(streamId: 0, offset: 0, fillingPayload, fin: true),
                out QuicTransportErrorCode fillErrorCode));
            Assert.Equal(default, fillErrorCode);

            byte[] destination = new byte[totalLength];
            Assert.True(state.TryReadStreamData(
                0,
                destination,
                out int bytesWritten,
                out bool completed,
                out _,
                out _,
                out QuicTransportErrorCode readErrorCode));
            Assert.Equal(default, readErrorCode);
            Assert.Equal(totalLength, bytesWritten);
            Assert.True(completed);
            Assert.Equal(expected, destination);
            Assert.Equal(default, state.CaptureReceiveRetentionSnapshot());
        });
    }

    [Fact]
    public void InterleavedStreamCanReachTerminalStateAfterThreadHandoff()
    {
        const int segmentLength = 4;
        const int segmentCount = 8;
        const int totalLength = ((segmentCount * 2) + 1) * segmentLength;
        QuicConnectionStreamState state = CreateServerReceiveState();
        byte[] expected = Enumerable.Repeat((byte)0x20, totalLength).ToArray();

        for (int index = 0; index < segmentCount; index++)
        {
            byte[] payload = Enumerable.Repeat((byte)(0x80 + index), segmentLength).ToArray();
            int offset = ((index * 2) + 1) * segmentLength;
            payload.CopyTo(expected, offset);
            Assert.True(state.TryReceiveStreamFrame(
                ParseStreamFrame(streamId: 0, (ulong)offset, payload, fin: false),
                out QuicTransportErrorCode seedErrorCode));
            Assert.Equal(default, seedErrorCode);
        }

        Exception? workerException = null;
        Thread worker = new(() =>
        {
            try
            {
                byte[] fillingPayload = Enumerable.Repeat((byte)0x20, totalLength).ToArray();
                Assert.True(state.TryReceiveStreamFrame(
                    ParseStreamFrame(streamId: 0, offset: 0, fillingPayload, fin: true),
                    out QuicTransportErrorCode fillErrorCode));
                Assert.Equal(default, fillErrorCode);

                byte[] destination = new byte[totalLength];
                Assert.True(state.TryReadStreamData(
                    0,
                    destination,
                    out int bytesWritten,
                    out bool completed,
                    out _,
                    out _,
                    out QuicTransportErrorCode readErrorCode));
                Assert.Equal(default, readErrorCode);
                Assert.Equal(totalLength, bytesWritten);
                Assert.True(completed);
                Assert.Equal(expected, destination);
            }
            catch (Exception exception)
            {
                workerException = exception;
            }
        });

        worker.Start();
        Assert.True(worker.Join(TimeSpan.FromSeconds(10)));
        Assert.Null(workerException);
        Assert.Equal(default, state.CaptureReceiveRetentionSnapshot());
    }

    private static QuicConnectionStreamState CreateServerReceiveState(ulong receiveLimit = 4096)
    {
        return new QuicConnectionStreamState(new QuicConnectionStreamStateOptions(
            IsServer: true,
            InitialConnectionReceiveLimit: receiveLimit,
            InitialConnectionSendLimit: 4096,
            InitialIncomingBidirectionalStreamLimit: 16,
            InitialIncomingUnidirectionalStreamLimit: 16,
            InitialPeerBidirectionalStreamLimit: 16,
            InitialPeerUnidirectionalStreamLimit: 16,
            InitialLocalBidirectionalReceiveLimit: receiveLimit,
            InitialPeerBidirectionalReceiveLimit: receiveLimit,
            InitialPeerUnidirectionalReceiveLimit: receiveLimit,
            InitialLocalBidirectionalSendLimit: 4096,
            InitialLocalUnidirectionalSendLimit: 4096,
            InitialPeerBidirectionalSendLimit: 4096));
    }

    private static QuicStreamFrame ParseStreamFrame(ulong streamId, ulong offset, ReadOnlySpan<byte> payload, bool fin)
    {
        byte frameType = QuicStreamFrameBits.StreamFrameTypeMinimum | QuicStreamFrameBits.LengthBitMask;
        if (offset != 0)
        {
            frameType |= QuicStreamFrameBits.OffsetBitMask;
        }

        if (fin)
        {
            frameType |= QuicStreamFrameBits.FinBitMask;
        }

        byte[] buffer = new byte[payload.Length + 32];
        Assert.True(QuicFrameCodec.TryFormatStreamFrame(frameType, streamId, offset, payload, buffer, out int bytesWritten));
        Assert.True(QuicStreamParser.TryParseStreamFrame(buffer.AsSpan(0, bytesWritten), out QuicStreamFrame frame));
        Assert.Equal(streamId, frame.StreamId.Value);
        Assert.Equal(offset, frame.Offset);
        Assert.Equal(payload.Length, frame.StreamDataLength);
        Assert.Equal(fin, frame.IsFin);
        Assert.True(payload.SequenceEqual(frame.StreamData));
        return frame;
    }
}
