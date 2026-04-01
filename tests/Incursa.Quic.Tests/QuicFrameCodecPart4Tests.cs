namespace Incursa.Quic.Tests;

public sealed class QuicFrameCodecPart4Tests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P12-0003")]
    [Requirement("REQ-QUIC-RFC9000-S19P12-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P12-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P12-0006")]
    [Trait("Category", "Positive")]
    public void TryParseDataBlockedFrame_ParsesAndFormatsTheMaximumDataField()
    {
        QuicDataBlockedFrame frame = new(0x1234_5678);
        byte[] encoded = QuicFrameTestData.BuildDataBlockedFrame(frame);

        Assert.True(QuicFrameCodec.TryParseDataBlockedFrame(encoded, out QuicDataBlockedFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.MaximumData, parsed.MaximumData);
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[16];
        Assert.True(QuicFrameCodec.TryFormatDataBlockedFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P12-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P12-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P12-0006")]
    [Trait("Category", "Negative")]
    public void TryParseDataBlockedFrame_RejectsTruncatedInput()
    {
        byte[] encoded = QuicFrameTestData.BuildDataBlockedFrame(new QuicDataBlockedFrame(0x01));

        Assert.False(QuicFrameCodec.TryParseDataBlockedFrame(encoded[..^1], out _, out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P13-0003")]
    [Requirement("REQ-QUIC-RFC9000-S19P13-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P13-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P13-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P13-0007")]
    [Requirement("REQ-QUIC-RFC9000-S19P13-0008")]
    [Trait("Category", "Positive")]
    public void TryParseStreamDataBlockedFrame_ParsesAndFormatsTheFrameFields()
    {
        QuicStreamDataBlockedFrame frame = new(0x06, 0x1234_5678);
        byte[] encoded = QuicFrameTestData.BuildStreamDataBlockedFrame(frame);

        Assert.True(QuicFrameCodec.TryParseStreamDataBlockedFrame(encoded, out QuicStreamDataBlockedFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.StreamId, parsed.StreamId);
        Assert.Equal(frame.MaximumStreamData, parsed.MaximumStreamData);
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicFrameCodec.TryFormatStreamDataBlockedFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P13-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P13-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P13-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P13-0007")]
    [Requirement("REQ-QUIC-RFC9000-S19P13-0008")]
    [Trait("Category", "Negative")]
    public void TryParseStreamDataBlockedFrame_RejectsTruncatedInput()
    {
        byte[] encoded = QuicFrameTestData.BuildStreamDataBlockedFrame(new QuicStreamDataBlockedFrame(0x06, 0x01));

        Assert.False(QuicFrameCodec.TryParseStreamDataBlockedFrame(encoded[..^1], out _, out _));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0007")]
    [Trait("Category", "Positive")]
    public void TryParseStreamsBlockedFrame_ParsesAndFormatsBidirectionalAndUnidirectionalVariants(bool isBidirectional)
    {
        QuicStreamsBlockedFrame frame = new(isBidirectional, 0x1234);
        byte[] encoded = QuicFrameTestData.BuildStreamsBlockedFrame(frame);

        Assert.True(QuicFrameCodec.TryParseStreamsBlockedFrame(encoded, out QuicStreamsBlockedFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.IsBidirectional, parsed.IsBidirectional);
        Assert.Equal(frame.MaximumStreams, parsed.MaximumStreams);
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[16];
        Assert.True(QuicFrameCodec.TryFormatStreamsBlockedFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0007")]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0008")]
    [Trait("Category", "Positive")]
    public void TryParseStreamsBlockedFrame_AcceptsValueAtTheEncodingLimit(bool isBidirectional)
    {
        ulong limit = 1UL << 60;
        QuicStreamsBlockedFrame frame = new(isBidirectional, limit);
        byte[] encoded = QuicFrameTestData.BuildStreamsBlockedFrame(frame);

        Assert.True(QuicFrameCodec.TryParseStreamsBlockedFrame(encoded, out QuicStreamsBlockedFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.IsBidirectional, parsed.IsBidirectional);
        Assert.Equal(limit, parsed.MaximumStreams);
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[16];
        Assert.True(QuicFrameCodec.TryFormatStreamsBlockedFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0008")]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0009")]
    [Trait("Category", "Negative")]
    public void TryParseStreamsBlockedFrame_RejectsValuesAboveTheEncodingLimit()
    {
        QuicStreamsBlockedFrame frame = new(true, (1UL << 60) + 1);
        byte[] encoded = QuicFrameTestData.BuildStreamsBlockedFrame(frame);

        Assert.False(QuicFrameCodec.TryParseStreamsBlockedFrame(encoded, out _, out _));
        Assert.False(QuicFrameCodec.TryFormatStreamsBlockedFrame(frame, stackalloc byte[16], out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0003")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0007")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0008")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0009")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0010")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0012")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0013")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0019")]
    [Requirement("REQ-QUIC-RFC9000-S5P1P2-0008")]
    [Requirement("REQ-QUIC-RFC9000-S5P1P1-0005")]
    [Trait("Category", "Positive")]
    public void TryParseNewConnectionIdFrame_ParsesAndFormatsTheEncodedFields()
    {
        byte[] connectionId = [0x10, 0x11, 0x12, 0x13];
        byte[] statelessResetToken = [
            0x20, 0x21, 0x22, 0x23,
            0x24, 0x25, 0x26, 0x27,
            0x28, 0x29, 0x2A, 0x2B,
            0x2C, 0x2D, 0x2E, 0x2F];

        QuicNewConnectionIdFrame frame = new(0x06, 0x04, connectionId, statelessResetToken);
        byte[] encoded = QuicFrameTestData.BuildNewConnectionIdFrame(frame);

        Assert.True(QuicFrameCodec.TryParseNewConnectionIdFrame(encoded, out QuicNewConnectionIdFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.SequenceNumber, parsed.SequenceNumber);
        Assert.Equal(frame.RetirePriorTo, parsed.RetirePriorTo);
        Assert.True(connectionId.AsSpan().SequenceEqual(parsed.ConnectionId));
        Assert.True(statelessResetToken.AsSpan().SequenceEqual(parsed.StatelessResetToken));
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[64];
        Assert.True(QuicFrameCodec.TryFormatNewConnectionIdFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(20)]
    [Requirement("REQ-QUIC-RFC9000-S5P1P2-0008")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0010")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0011")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0012")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0013")]
    [Requirement("REQ-QUIC-RFC9000-S5P1P1-0005")]
    [Trait("Category", "Positive")]
    public void TryParseNewConnectionIdFrame_AcceptsBoundaryConnectionIdLengths(int connectionIdLength)
    {
        byte[] connectionId = Enumerable.Repeat((byte)0xDA, connectionIdLength).ToArray();
        byte[] statelessResetToken = Enumerable.Repeat((byte)0x5C, 16).ToArray();
        QuicNewConnectionIdFrame frame = new(0x09, 0x01, connectionId, statelessResetToken);
        byte[] encoded = QuicFrameTestData.BuildNewConnectionIdFrame(frame);

        Assert.True(QuicFrameCodec.TryParseNewConnectionIdFrame(encoded, out QuicNewConnectionIdFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.SequenceNumber, parsed.SequenceNumber);
        Assert.Equal(frame.RetirePriorTo, parsed.RetirePriorTo);
        Assert.Equal(connectionIdLength, parsed.ConnectionId.Length);
        Assert.True(connectionId.AsSpan().SequenceEqual(parsed.ConnectionId));
        Assert.True(statelessResetToken.AsSpan().SequenceEqual(parsed.StatelessResetToken));
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[64];
        Assert.True(QuicFrameCodec.TryFormatNewConnectionIdFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0010")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0011")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0012")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0013")]
    [Trait("Category", "Negative")]
    public void TryParseNewConnectionIdFrame_RejectsInvalidConnectionIdLengthValues()
    {
        byte[] statelessResetToken = Enumerable.Repeat((byte)0x5C, 16).ToArray();

        QuicNewConnectionIdFrame zeroLengthFrame = new(0x01, 0x00, Array.Empty<byte>(), statelessResetToken);
        byte[] zeroLengthEncoded = QuicFrameTestData.BuildNewConnectionIdFrame(zeroLengthFrame);
        Assert.False(QuicFrameCodec.TryParseNewConnectionIdFrame(zeroLengthEncoded, out _, out _));

        QuicNewConnectionIdFrame longLengthFrame = new(0x02, 0x01, Enumerable.Repeat((byte)0xDA, 21).ToArray(), statelessResetToken);
        byte[] longLengthEncoded = QuicFrameTestData.BuildNewConnectionIdFrame(longLengthFrame);
        Assert.False(QuicFrameCodec.TryParseNewConnectionIdFrame(longLengthEncoded, out _, out _));

        QuicNewConnectionIdFrame invalidTokenFrame = new(0x03, 0x01, [0xAA], Enumerable.Repeat((byte)0xCC, 15).ToArray());
        Assert.False(QuicFrameCodec.TryFormatNewConnectionIdFrame(invalidTokenFrame, stackalloc byte[64], out _));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(17)]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0008")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0012")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0013")]
    [Trait("Category", "Negative")]
    public void TryParseNewConnectionIdFrame_RejectsTruncatedInput(int truncateBy)
    {
        byte[] connectionId = [0x10];
        byte[] statelessResetToken = [
            0x20, 0x21, 0x22, 0x23,
            0x24, 0x25, 0x26, 0x27,
            0x28, 0x29, 0x2A, 0x2B,
            0x2C, 0x2D, 0x2E, 0x2F];
        QuicNewConnectionIdFrame frame = new(0x06, 0x04, connectionId, statelessResetToken);
        byte[] encoded = QuicFrameTestData.BuildNewConnectionIdFrame(frame);

        Assert.False(QuicFrameCodec.TryParseNewConnectionIdFrame(encoded[..Math.Max(0, encoded.Length - truncateBy)], out _, out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0019")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0020")]
    [Trait("Category", "Negative")]
    public void TryParseNewConnectionIdFrame_RejectsRetirePriorToGreaterThanSequenceNumber()
    {
        byte[] connectionId = [0x10, 0x11];
        byte[] statelessResetToken = [
            0x20, 0x21, 0x22, 0x23,
            0x24, 0x25, 0x26, 0x27,
            0x28, 0x29, 0x2A, 0x2B,
            0x2C, 0x2D, 0x2E, 0x2F];
        QuicNewConnectionIdFrame frame = new(0x03, 0x04, connectionId, statelessResetToken);
        byte[] encoded = QuicFrameTestData.BuildNewConnectionIdFrame(frame);

        Assert.False(QuicFrameCodec.TryParseNewConnectionIdFrame(encoded, out _, out _));
        Assert.False(QuicFrameCodec.TryFormatNewConnectionIdFrame(frame, stackalloc byte[64], out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S5P1P2-0004")]
    [Requirement("REQ-QUIC-RFC9000-S5P1P2-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P16-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P16-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P16-0006")]
    [Trait("Category", "Positive")]
    public void TryParseRetireConnectionIdFrame_ParsesAndFormatsTheSequenceNumber()
    {
        QuicRetireConnectionIdFrame frame = new(0x1234_5678);
        byte[] encoded = QuicFrameTestData.BuildRetireConnectionIdFrame(frame);

        Assert.True(QuicFrameCodec.TryParseRetireConnectionIdFrame(encoded, out QuicRetireConnectionIdFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.SequenceNumber, parsed.SequenceNumber);
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[16];
        Assert.True(QuicFrameCodec.TryFormatRetireConnectionIdFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Theory]
    [InlineData(1)]
    [Requirement("REQ-QUIC-RFC9000-S5P1P2-0004")]
    [Requirement("REQ-QUIC-RFC9000-S5P1P2-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P16-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P16-0006")]
    [Trait("Category", "Negative")]
    public void TryParseRetireConnectionIdFrame_RejectsTruncatedInput(int truncateBy)
    {
        QuicRetireConnectionIdFrame frame = new(0x01);
        byte[] encoded = QuicFrameTestData.BuildRetireConnectionIdFrame(frame);

        Assert.False(QuicFrameCodec.TryParseRetireConnectionIdFrame(encoded[..Math.Max(0, encoded.Length - truncateBy)], out _, out _));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    [Requirement("REQ-QUIC-RFC9000-S19P17-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P17-0003")]
    [Requirement("REQ-QUIC-RFC9000-S19P17-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P17-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P18-0001")]
    [Requirement("REQ-QUIC-RFC9000-S19P18-0002")]
    [Trait("Category", "Positive")]
    public void TryParsePathFrames_ParsesAndFormatsTheEightBytePayload(bool isChallenge)
    {
        byte[] data = [
            0xA0, 0xA1, 0xA2, 0xA3,
            0xA4, 0xA5, 0xA6, 0xA7];

        if (isChallenge)
        {
            QuicPathChallengeFrame frame = new(data);
            byte[] encoded = QuicFrameTestData.BuildPathChallengeFrame(frame);

            Assert.True(QuicFrameCodec.TryParsePathChallengeFrame(encoded, out QuicPathChallengeFrame parsed, out int bytesConsumed));
            Assert.True(data.AsSpan().SequenceEqual(parsed.Data));
            Assert.Equal(encoded.Length, bytesConsumed);

            Span<byte> destination = stackalloc byte[16];
            Assert.True(QuicFrameCodec.TryFormatPathChallengeFrame(parsed, destination, out int bytesWritten));
            Assert.Equal(encoded.Length, bytesWritten);
            Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
        }
        else
        {
            QuicPathResponseFrame frame = new(data);
            byte[] encoded = QuicFrameTestData.BuildPathResponseFrame(frame);

            Assert.True(QuicFrameCodec.TryParsePathResponseFrame(encoded, out QuicPathResponseFrame parsed, out int bytesConsumed));
            Assert.True(data.AsSpan().SequenceEqual(parsed.Data));
            Assert.Equal(encoded.Length, bytesConsumed);

            Span<byte> destination = stackalloc byte[16];
            Assert.True(QuicFrameCodec.TryFormatPathResponseFrame(parsed, destination, out int bytesWritten));
            Assert.Equal(encoded.Length, bytesWritten);
            Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
        }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    [Requirement("REQ-QUIC-RFC9000-S19P17-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P17-0003")]
    [Requirement("REQ-QUIC-RFC9000-S19P17-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P17-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P18-0001")]
    [Requirement("REQ-QUIC-RFC9000-S19P18-0002")]
    [Trait("Category", "Negative")]
    public void TryParsePathFrames_RejectsTruncatedInput(bool isChallenge)
    {
        byte[] invalidData = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6];
        byte[] validData = [
            0xA0, 0xA1, 0xA2, 0xA3,
            0xA4, 0xA5, 0xA6, 0xA7];

        if (isChallenge)
        {
            QuicPathChallengeFrame invalidFrame = new(invalidData);
            Assert.False(QuicFrameCodec.TryFormatPathChallengeFrame(invalidFrame, stackalloc byte[16], out _));

            byte[] encoded = QuicFrameTestData.BuildPathChallengeFrame(new QuicPathChallengeFrame(validData));
            Assert.False(QuicFrameCodec.TryParsePathChallengeFrame(encoded[..^1], out _, out _));
        }
        else
        {
            QuicPathResponseFrame invalidFrame = new(invalidData);
            Assert.False(QuicFrameCodec.TryFormatPathResponseFrame(invalidFrame, stackalloc byte[16], out _));

            byte[] encoded = QuicFrameTestData.BuildPathResponseFrame(new QuicPathResponseFrame(validData));
            Assert.False(QuicFrameCodec.TryParsePathResponseFrame(encoded[..^1], out _, out _));
        }
    }
}
