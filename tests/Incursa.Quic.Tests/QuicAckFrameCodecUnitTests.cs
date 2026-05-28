// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class QuicAckFrameCodecUnitTests
{
    [Fact]
    public void TryParseAckFrame_CommonNoAdditionalRanges_PreservesFieldsAndBytes()
    {
        QuicAckFrame frame = new()
        {
            FrameType = 0x02,
            LargestAcknowledged = 128,
            AckDelay = 16,
            FirstAckRange = 7,
        };

        byte[] encoded = QuicFrameTestData.BuildAckFrame(frame);

        Assert.True(QuicFrameCodec.TryParseAckFrame(encoded, out QuicAckFrame parsed, out int bytesConsumed));
        Assert.Equal(encoded.Length, bytesConsumed);
        Assert.Equal(0x02, parsed.FrameType);
        Assert.Equal((ulong)128, parsed.LargestAcknowledged);
        Assert.Equal((ulong)16, parsed.AckDelay);
        Assert.Equal((ulong)7, parsed.FirstAckRange);
        Assert.Empty(parsed.AdditionalRanges);
        Assert.Null(parsed.EcnCounts);

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicFrameCodec.TryFormatAckFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    public void TryParseAckFrame_MultipleRanges_PreservesOrderingAndBytes()
    {
        QuicAckFrame frame = new()
        {
            FrameType = 0x02,
            LargestAcknowledged = 128,
            AckDelay = 16,
            FirstAckRange = 7,
            AdditionalRanges =
            [
                new QuicAckRange(1, 3, 115, 118),
                new QuicAckRange(0, 1, 112, 113),
                new QuicAckRange(2, 0, 108, 108),
            ],
        };

        byte[] encoded = QuicFrameTestData.BuildAckFrame(frame);

        Assert.True(QuicFrameCodec.TryParseAckFrame(encoded, out QuicAckFrame parsed, out int bytesConsumed));
        Assert.Equal(encoded.Length, bytesConsumed);
        Assert.Equal(frame.AdditionalRanges.Length, parsed.AdditionalRanges.Length);
        for (int index = 0; index < frame.AdditionalRanges.Length; index++)
        {
            Assert.Equal(frame.AdditionalRanges[index].Gap, parsed.AdditionalRanges[index].Gap);
            Assert.Equal(frame.AdditionalRanges[index].AckRangeLength, parsed.AdditionalRanges[index].AckRangeLength);
            Assert.Equal(frame.AdditionalRanges[index].SmallestAcknowledged, parsed.AdditionalRanges[index].SmallestAcknowledged);
            Assert.Equal(frame.AdditionalRanges[index].LargestAcknowledged, parsed.AdditionalRanges[index].LargestAcknowledged);
        }

        Span<byte> destination = stackalloc byte[64];
        Assert.True(QuicFrameCodec.TryFormatAckFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    public void TryParseAckFrame_AckEcnNoAdditionalRanges_PreservesEcnCountsAndBytes()
    {
        QuicAckFrame frame = new()
        {
            FrameType = 0x03,
            LargestAcknowledged = 128,
            AckDelay = 16,
            FirstAckRange = 7,
            EcnCounts = new QuicEcnCounts(32, 0, 1),
        };

        byte[] encoded = QuicFrameTestData.BuildAckFrame(frame);

        Assert.True(QuicFrameCodec.TryParseAckFrame(encoded, out QuicAckFrame parsed, out int bytesConsumed));
        Assert.Equal(encoded.Length, bytesConsumed);
        Assert.Equal(0x03, parsed.FrameType);
        Assert.Empty(parsed.AdditionalRanges);
        Assert.True(parsed.EcnCounts.HasValue);
        Assert.Equal((ulong)32, parsed.EcnCounts.Value.Ect0Count);
        Assert.Equal((ulong)0, parsed.EcnCounts.Value.Ect1Count);
        Assert.Equal((ulong)1, parsed.EcnCounts.Value.EcnCeCount);

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicFrameCodec.TryFormatAckFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    public void TryParseAckFrame_AckThenStreamSequence_PreservesFrameOrdering()
    {
        byte[] encodedAck = QuicFrameTestData.BuildAckFrame(new QuicAckFrame
        {
            FrameType = 0x02,
            LargestAcknowledged = 128,
            AckDelay = 16,
            FirstAckRange = 7,
        });
        byte[] streamData = [0x48, 0x65, 0x6C, 0x6C, 0x6F];
        Span<byte> streamBuffer = stackalloc byte[32];
        Assert.True(QuicFrameCodec.TryFormatStreamFrame(0x0F, 0, 0, streamData, streamBuffer, out int streamBytesWritten));
        byte[] payload = new byte[encodedAck.Length + streamBytesWritten];
        encodedAck.CopyTo(payload.AsSpan());
        streamBuffer[..streamBytesWritten].CopyTo(payload.AsSpan(encodedAck.Length));

        Assert.True(QuicFrameCodec.TryParseAckFrame(payload, out QuicAckFrame ackFrame, out int ackBytesConsumed));
        Assert.Equal(encodedAck.Length, ackBytesConsumed);
        Assert.Equal((ulong)128, ackFrame.LargestAcknowledged);

        Assert.True(QuicStreamParser.TryParseStreamFrame(payload.AsSpan(ackBytesConsumed), out QuicStreamFrame streamFrame));
        Assert.Equal(streamBytesWritten, streamFrame.ConsumedLength);
        Assert.Equal((ulong)0, streamFrame.StreamId.Value);
        Assert.True(streamData.AsSpan().SequenceEqual(streamFrame.StreamData));
    }

    [Fact]
    public void TryParseAckFrame_UnsupportedFrameTypeStillFailsWithoutConsumingBytes()
    {
        byte[] pingFrame = [0x01];

        Assert.False(QuicFrameCodec.TryParseAckFrame(pingFrame, out _, out int bytesConsumed));
        Assert.Equal(0, bytesConsumed);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void TryParseAckFrame_And_TryFormatAckFrame_RoundTripRangesAndEcnCounts(bool includeEcnCounts)
    {
        QuicAckFrame frame = CreateAckFrame(includeEcnCounts);
        byte[] encoded = QuicFrameTestData.BuildAckFrame(frame);

        Assert.True(QuicFrameCodec.TryParseAckFrame(encoded, out QuicAckFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.FrameType, parsed.FrameType);
        Assert.Equal(frame.LargestAcknowledged, parsed.LargestAcknowledged);
        Assert.Equal(frame.AckDelay, parsed.AckDelay);
        Assert.Equal(frame.FirstAckRange, parsed.FirstAckRange);
        Assert.Equal(frame.AdditionalRanges.Length, parsed.AdditionalRanges.Length);
        for (int index = 0; index < frame.AdditionalRanges.Length; index++)
        {
            Assert.Equal(frame.AdditionalRanges[index].Gap, parsed.AdditionalRanges[index].Gap);
            Assert.Equal(frame.AdditionalRanges[index].AckRangeLength, parsed.AdditionalRanges[index].AckRangeLength);
            Assert.Equal(frame.AdditionalRanges[index].SmallestAcknowledged, parsed.AdditionalRanges[index].SmallestAcknowledged);
            Assert.Equal(frame.AdditionalRanges[index].LargestAcknowledged, parsed.AdditionalRanges[index].LargestAcknowledged);
        }

        if (includeEcnCounts)
        {
            QuicEcnCounts frameEcnCounts = frame.EcnCounts.GetValueOrDefault();
            QuicEcnCounts parsedEcnCounts = parsed.EcnCounts.GetValueOrDefault();

            Assert.True(parsed.EcnCounts.HasValue);
            Assert.Equal(frameEcnCounts.Ect0Count, parsedEcnCounts.Ect0Count);
            Assert.Equal(frameEcnCounts.Ect1Count, parsedEcnCounts.Ect1Count);
            Assert.Equal(frameEcnCounts.EcnCeCount, parsedEcnCounts.EcnCeCount);
        }
        else
        {
            Assert.Null(parsed.EcnCounts);
        }

        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[64];
        Assert.True(QuicFrameCodec.TryFormatAckFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void TryParseAckFrame_RejectsTruncatedInput(bool includeEcnCounts)
    {
        byte[] encoded = QuicFrameTestData.BuildAckFrame(CreateAckFrame(includeEcnCounts));

        Assert.False(QuicFrameCodec.TryParseAckFrame(encoded[..^1], out _, out _));
    }

    [Fact]
    public void TryParseAckFrame_And_TryFormatAckFrame_RejectFirstAckRangeGreaterThanLargestAcknowledged()
    {
        QuicAckFrame invalidFrame = new()
        {
            FrameType = 0x02,
            LargestAcknowledged = 0x03,
            AckDelay = 0x01,
            FirstAckRange = 0x04,
        };

        byte[] encoded = QuicFrameTestData.BuildAckFrame(invalidFrame);
        Assert.False(QuicFrameCodec.TryParseAckFrame(encoded, out _, out _));

        Span<byte> destination = stackalloc byte[16];
        Assert.False(QuicFrameCodec.TryFormatAckFrame(invalidFrame, destination, out _));
    }

    [Fact]
    public void TryParseAckFrame_And_TryFormatAckFrame_RejectImpossibleAdditionalRangeLayout()
    {
        QuicAckFrame invalidFrame = new()
        {
            FrameType = 0x02,
            LargestAcknowledged = 0x10,
            AckDelay = 0x01,
            FirstAckRange = 0x00,
            AdditionalRanges =
            [
                new QuicAckRange(0x0F, 0x00, 0x00, 0x00),
            ],
        };

        byte[] encoded = QuicFrameTestData.BuildAckFrame(invalidFrame);
        Assert.False(QuicFrameCodec.TryParseAckFrame(encoded, out _, out _));

        Span<byte> destination = stackalloc byte[16];
        Assert.False(QuicFrameCodec.TryFormatAckFrame(invalidFrame, destination, out _));
    }

    private static QuicAckFrame CreateAckFrame(bool includeEcnCounts)
    {
        ulong largestAcknowledged = 0x1234;
        ulong firstAckRange = 0x04;
        ulong firstSmallestAcknowledged = largestAcknowledged - firstAckRange;
        QuicAckRange firstAdditionalRange = QuicFrameTestData.BuildAckRange(firstSmallestAcknowledged, 0x01, 0x02);
        QuicAckRange secondAdditionalRange = QuicFrameTestData.BuildAckRange(firstAdditionalRange.SmallestAcknowledged, 0x00, 0x00);

        return new QuicAckFrame
        {
            FrameType = includeEcnCounts ? (byte)0x03 : (byte)0x02,
            LargestAcknowledged = largestAcknowledged,
            AckDelay = 0x25,
            FirstAckRange = firstAckRange,
            AdditionalRanges =
            [
                firstAdditionalRange,
                secondAdditionalRange,
            ],
            EcnCounts = includeEcnCounts ? new QuicEcnCounts(0x11, 0x12, 0x13) : null,
        };
    }
}
