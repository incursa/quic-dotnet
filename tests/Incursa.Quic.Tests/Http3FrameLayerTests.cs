namespace Incursa.Quic.Tests;

public sealed class Http3FrameLayerTests
{
    [Fact]
    public void FrameWriter_And_Reader_RoundTripDataFrame()
    {
        byte[] encoded = Http3FrameWriter.WriteData([0x01, 0x02, 0x03]);

        Http3Frame frame = ReadSingle(encoded);

        Http3DataFrame dataFrame = Assert.IsType<Http3DataFrame>(frame);
        Assert.Equal("0003010203", Convert.ToHexString(encoded));
        Assert.Equal([0x01, 0x02, 0x03], dataFrame.Data.ToArray());
    }

    [Fact]
    public void FrameWriter_And_Reader_RoundTripHeadersFrame()
    {
        byte[] encoded = Http3FrameWriter.WriteHeaders([0x00, 0x00, 0xC1]);

        Http3HeadersFrame frame = Assert.IsType<Http3HeadersFrame>(ReadSingle(encoded));

        Assert.Equal((ulong)Http3FrameType.Headers, frame.Type);
        Assert.Equal([0x00, 0x00, 0xC1], frame.EncodedFieldSection.ToArray());
    }

    [Fact]
    public void FrameWriter_And_Reader_RoundTripSettingsFrame()
    {
        byte[] encoded = Http3FrameWriter.WriteSettings(
        [
            new Http3Setting(0x01, 128),
            new Http3Setting(0x06, 4096),
        ]);

        Http3SettingsFrame frame = Assert.IsType<Http3SettingsFrame>(ReadSingle(encoded));

        Assert.Equal(
            [
                new Http3Setting(0x01, 128),
                new Http3Setting(0x06, 4096),
            ],
            frame.Settings);
    }

    [Theory]
    [InlineData((int)Http3FrameType.CancelPush, 17UL)]
    [InlineData((int)Http3FrameType.GoAway, 4UL)]
    [InlineData((int)Http3FrameType.MaxPushId, 9UL)]
    public void FrameWriter_And_Reader_RoundTripSingleIntegerFrames(int frameType, ulong value)
    {
        byte[] encoded = frameType switch
        {
            (int)Http3FrameType.CancelPush => Http3FrameWriter.WriteCancelPush(value),
            (int)Http3FrameType.GoAway => Http3FrameWriter.WriteGoAway(value),
            (int)Http3FrameType.MaxPushId => Http3FrameWriter.WriteMaxPushId(value),
            _ => throw new ArgumentOutOfRangeException(nameof(frameType)),
        };

        Http3IdFrame frame = Assert.IsAssignableFrom<Http3IdFrame>(ReadSingle(encoded));

        Assert.Equal((ulong)frameType, frame.Type);
        Assert.Equal(value, frame.Identifier);
        Assert.Equal(1UL, frame.Length);
    }

    [Fact]
    public void FrameWriter_And_Reader_RoundTripPushPromiseFrame()
    {
        byte[] encoded = Http3FrameWriter.WritePushPromise(3, [0x00, 0x00, 0xC1]);

        Http3PushPromiseFrame frame = Assert.IsType<Http3PushPromiseFrame>(ReadSingle(encoded));

        Assert.Equal(3UL, frame.PushId);
        Assert.Equal([0x00, 0x00, 0xC1], frame.EncodedFieldSection);
    }

    [Fact]
    public void FrameReader_ReturnsUnknownFrameForUnknownType()
    {
        byte[] encoded = Http3FrameWriter.WriteFrame(0x41, [0xAA, 0xBB]);

        Http3UnknownFrame frame = Assert.IsType<Http3UnknownFrame>(ReadSingle(encoded));

        Assert.Equal(0x41UL, frame.Type);
        Assert.False(frame.IsReserved);
        Assert.Equal([0xAA, 0xBB], frame.Payload);
    }

    [Theory]
    [InlineData(0x02UL)]
    [InlineData(0x21UL)]
    [InlineData(0x40UL)]
    public void FrameReader_PreservesReservedFrameTypesAsUnknownFrames(ulong frameType)
    {
        byte[] encoded = Http3FrameWriter.WriteFrame(frameType, [0xAA]);

        Http3UnknownFrame frame = Assert.IsType<Http3UnknownFrame>(ReadSingle(encoded));

        Assert.Equal(frameType, frame.Type);
        Assert.True(frame.IsReserved);
    }

    [Fact]
    public void FrameReader_ParsesHeadersAndPayloadSplitAcrossSingleByteReads()
    {
        byte[] payload = Enumerable.Range(0, 64).Select(value => (byte)value).ToArray();
        byte[] encoded = Http3FrameWriter.WriteData(payload);
        Http3FrameReader reader = new();
        List<Http3Frame> frames = [];

        foreach (byte current in encoded)
        {
            frames.AddRange(reader.Read([current]));
        }

        Http3DataFrame frame = Assert.IsType<Http3DataFrame>(Assert.Single(frames));
        Assert.Equal(payload, frame.Data.ToArray());
        Assert.Equal(0, reader.PendingByteCount);
    }

    [Fact]
    public void FrameReader_ParsesMultipleFramesAcrossSmallReads()
    {
        byte[] encoded =
        [
            .. Http3FrameWriter.WriteData([0x01]),
            .. Http3FrameWriter.WriteHeaders([0x02, 0x03]),
            .. Http3FrameWriter.WriteGoAway(0),
        ];
        Http3FrameReader reader = new();
        List<Http3Frame> frames = [];

        for (int index = 0; index < encoded.Length; index += 2)
        {
            int count = Math.Min(2, encoded.Length - index);
            frames.AddRange(reader.Read(encoded.AsSpan(index, count)));
        }

        Assert.Collection(
            frames,
            frame => Assert.IsType<Http3DataFrame>(frame),
            frame => Assert.IsType<Http3HeadersFrame>(frame),
            frame => Assert.IsType<Http3GoAwayFrame>(frame));
    }

    [Fact]
    public void FrameReader_RejectsTruncatedHeaderAtEndOfStream()
    {
        Http3FrameReader reader = new();
        Assert.Empty(reader.Read([0x40]));

        Http3Exception exception = Assert.Throws<Http3Exception>(reader.Complete);

        Assert.Equal(Http3ErrorCode.FrameError, exception.ErrorCode);
    }

    [Fact]
    public void FrameReader_RejectsTruncatedPayloadAtEndOfStream()
    {
        Http3FrameReader reader = new();
        Assert.Empty(reader.Read(Convert.FromHexString("00030102")));

        Http3Exception exception = Assert.Throws<Http3Exception>(reader.Complete);

        Assert.Equal(Http3ErrorCode.FrameError, exception.ErrorCode);
    }

    [Fact]
    public void FrameReader_RejectsSingleIntegerFrameWithExtraPayloadBytes()
    {
        byte[] encoded = Convert.FromHexString("03020102");

        Http3Exception exception = Assert.Throws<Http3Exception>(() => ReadSingle(encoded));

        Assert.Equal(Http3ErrorCode.FrameError, exception.ErrorCode);
    }

    [Fact]
    public void FrameReader_RejectsSettingsPayloadWithTruncatedPair()
    {
        byte[] encoded = Convert.FromHexString("040101");

        Http3Exception exception = Assert.Throws<Http3Exception>(() => ReadSingle(encoded));

        Assert.Equal(Http3ErrorCode.FrameError, exception.ErrorCode);
    }

    [Fact]
    public void FrameReader_RejectsDuplicateSettingsIdentifiers()
    {
        byte[] encoded = Http3FrameWriter.WriteFrame((ulong)Http3FrameType.Settings, [0x01, 0x02, 0x01, 0x03]);

        Http3Exception exception = Assert.Throws<Http3Exception>(() => ReadSingle(encoded));

        Assert.Equal(Http3ErrorCode.SettingsError, exception.ErrorCode);
    }

    [Fact]
    public void FrameReader_RejectsPushPromiseWithoutPushId()
    {
        byte[] encoded = Http3FrameWriter.WriteFrame((ulong)Http3FrameType.PushPromise, []);

        Http3Exception exception = Assert.Throws<Http3Exception>(() => ReadSingle(encoded));

        Assert.Equal(Http3ErrorCode.FrameError, exception.ErrorCode);
    }

    private static Http3Frame ReadSingle(byte[] encoded)
    {
        Http3FrameReader reader = new();
        Http3Frame frame = Assert.Single(reader.Read(encoded));
        Assert.Empty(reader.Complete());
        return frame;
    }
}
