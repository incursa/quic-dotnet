// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers;

namespace Incursa.Quic.Tests;

public sealed class Http3FrameLayerTests
{
    private static readonly byte[] PlaintextResponseBody = "Hello, World!"u8.ToArray();
    private static readonly byte[] JsonResponseBody = """{"message":"Hello, World!"}"""u8.ToArray();

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
    public void FrameWriter_DataFrameUsesExactLengthForLargePayload()
    {
        byte[] payload = Enumerable.Range(0, 16 * 1024)
            .Select(static value => (byte)(value % 251))
            .ToArray();

        byte[] encoded = Http3FrameWriter.WriteData(payload);

        Assert.Equal(
            Http3FrameWriter.GetFrameLength((ulong)Http3FrameType.Data, payload.Length),
            encoded.Length);
        Http3DataFrame frame = Assert.IsType<Http3DataFrame>(ReadSingle(encoded));
        Assert.Equal(payload, frame.Data.ToArray());
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
    public void FrameWriter_BufferWriterHeadersMatchesStandaloneHeadersFrame()
    {
        byte[] encodedFieldSection = EncodeResponseFieldSection("text/plain", PlaintextResponseBody.Length);
        ArrayBufferWriter<byte> writer = new();

        Http3FrameWriter.WriteHeaders(writer, encodedFieldSection);

        Assert.Equal(Http3FrameWriter.WriteHeaders(encodedFieldSection), writer.WrittenSpan.ToArray());
        Http3HeadersFrame frame = Assert.IsType<Http3HeadersFrame>(ReadSingle(writer.WrittenSpan.ToArray()));
        Assert.Equal(
            [
                new QPackFieldLine(":status", "200"),
                new QPackFieldLine("content-type", "text/plain"),
                new QPackFieldLine("content-length", PlaintextResponseBody.Length.ToString()),
            ],
            QPackDecoder.DecodeFieldSection(frame.EncodedFieldSection));
    }

    [Fact]
    public void FrameWriter_BufferWriterDataMatchesStandaloneDataFrame()
    {
        ArrayBufferWriter<byte> writer = new();

        Http3FrameWriter.WriteData(writer, JsonResponseBody);

        Assert.Equal(Http3FrameWriter.WriteData(JsonResponseBody), writer.WrittenSpan.ToArray());
        Http3DataFrame frame = Assert.IsType<Http3DataFrame>(ReadSingle(writer.WrittenSpan.ToArray()));
        Assert.Equal(JsonResponseBody, frame.Data.ToArray());
    }

    [Theory]
    [InlineData("text/plain", "Hello, World!")]
    [InlineData("application/json", """{"message":"Hello, World!"}""")]
    public void FrameWriter_BufferWriterResponseSequenceMatchesStandaloneHeadersAndData(string contentType, string bodyText)
    {
        byte[] body = System.Text.Encoding.UTF8.GetBytes(bodyText);
        byte[] encodedFieldSection = EncodeResponseFieldSection(contentType, body.Length);
        byte[] expected =
        [
            .. Http3FrameWriter.WriteHeaders(encodedFieldSection),
            .. Http3FrameWriter.WriteData(body),
        ];
        ArrayBufferWriter<byte> writer = new(Http3FrameWriter.GetFrameLength((ulong)Http3FrameType.Headers, encodedFieldSection.Length)
            + Http3FrameWriter.GetFrameLength((ulong)Http3FrameType.Data, body.Length));

        Http3FrameWriter.WriteHeaders(writer, encodedFieldSection);
        Http3FrameWriter.WriteData(writer, body);

        Assert.Equal(expected, writer.WrittenSpan.ToArray());
        Http3Frame[] frames = new Http3FrameReader().Read(writer.WrittenSpan);
        Assert.Collection(
            frames,
            frame =>
            {
                Http3HeadersFrame headersFrame = Assert.IsType<Http3HeadersFrame>(frame);
                Assert.Contains(
                    QPackDecoder.DecodeFieldSection(headersFrame.EncodedFieldSection),
                    header => header.Name == "content-type" && header.Value == contentType);
            },
            frame =>
            {
                Http3DataFrame dataFrame = Assert.IsType<Http3DataFrame>(frame);
                Assert.Equal(body, dataFrame.Data.ToArray());
            });
        Assert.Equal(expected.Length, writer.WrittenCount);
    }

    [Theory]
    [InlineData(
        "text/plain",
        13,
        "0000D95F4D07696E6375727361561D5765642C203237204D617920323032362031353A30303A303020474D54F554023133")]
    [InlineData(
        "application/json",
        27,
        "0000D95F4D07696E6375727361561D5765642C203237204D617920323032362031353A30303A303020474D54EE54023237")]
    public void QPackEncoder_ResponseFieldSectionBytesStayStable(string contentType, int contentLength, string expectedHex)
    {
        byte[] encoded = EncodeTechEmpowerResponseFieldSection(contentType, contentLength);

        Assert.Equal(expectedHex, Convert.ToHexString(encoded));
        Assert.Equal(
            [
                new QPackFieldLine(":status", "200"),
                new QPackFieldLine("server", "incursa"),
                new QPackFieldLine("date", "Wed, 27 May 2026 15:00:00 GMT"),
                new QPackFieldLine("content-type", contentType),
                new QPackFieldLine("content-length", contentLength.ToString()),
            ],
            QPackDecoder.DecodeFieldSection(encoded));
    }

    [Theory]
    [InlineData(
        "text/plain",
        "Hello, World!",
        "00005F09033230305F4D07696E6375727361561D5765642C203237204D617920323032362031353A30303A303020474D54F554023133")]
    [InlineData(
        "application/json",
        """{"message":"Hello, World!"}""",
        "00005F09033230305F4D07696E6375727361561D5765642C203237204D617920323032362031353A30303A303020474D54EE54023237")]
    public void ServerResponseBuilder_PreservesTechEmpowerFieldSectionAndFrameBytes(
        string contentType,
        string bodyText,
        string expectedFieldSectionHex)
    {
        byte[] body = System.Text.Encoding.UTF8.GetBytes(bodyText);
        Http3ServerResponse response = new(200, body, BuildTechEmpowerResponseHeaders(contentType, body.Length));

        IReadOnlyList<QPackFieldLine> headers = Http3Server.BuildResponseHeaders(response);
        byte[] encodedFieldSection = Http3Server.EncodeResponseFieldSection(headers);
        byte[] headersFrame = Http3FrameWriter.WriteHeaders(encodedFieldSection);
        byte[] dataFrame = Http3FrameWriter.WriteData(body);
        byte[] responseFrames = [.. headersFrame, .. dataFrame];

        Assert.Equal(expectedFieldSectionHex, Convert.ToHexString(encodedFieldSection));
        Assert.Equal(Http3FrameWriter.WriteHeaders(Convert.FromHexString(expectedFieldSectionHex)), headersFrame);
        Assert.Equal(Http3FrameWriter.WriteData(body), dataFrame);
        Assert.Equal([.. Http3FrameWriter.WriteHeaders(encodedFieldSection), .. Http3FrameWriter.WriteData(body)], responseFrames);
        Assert.Equal(
            [
                new QPackFieldLine(":status", "200"),
                new QPackFieldLine("server", "incursa"),
                new QPackFieldLine("date", "Wed, 27 May 2026 15:00:00 GMT"),
                new QPackFieldLine("content-type", contentType),
                new QPackFieldLine("content-length", body.Length.ToString()),
            ],
            headers);
        Assert.Equal(headers, QPackDecoder.DecodeFieldSection(encodedFieldSection));

        Http3Frame[] frames = new Http3FrameReader().Read(responseFrames);
        Assert.Collection(
            frames,
            frame =>
            {
                Http3HeadersFrame headersFrame = Assert.IsType<Http3HeadersFrame>(frame);
                Assert.Equal(encodedFieldSection, headersFrame.EncodedFieldSection.ToArray());
            },
            frame =>
            {
                Http3DataFrame data = Assert.IsType<Http3DataFrame>(frame);
                Assert.Equal(body, data.Data.ToArray());
            });
    }

    [Fact]
    public void ServerResponseBuilder_PreservesCustomHeadersAndSkipsDuplicateStatus()
    {
        Http3ServerResponse response = new(
            204,
            ReadOnlyMemory<byte>.Empty,
            [
                new QPackFieldLine("server", "incursa"),
                new QPackFieldLine(":status", "599"),
                new QPackFieldLine("x-custom", "one"),
                new QPackFieldLine("cache-control", "no-store"),
            ]);

        IReadOnlyList<QPackFieldLine> headers = Http3Server.BuildResponseHeaders(response);
        byte[] encodedFieldSection = Http3Server.EncodeResponseFieldSection(headers);

        Assert.Equal(
            [
                new QPackFieldLine(":status", "204"),
                new QPackFieldLine("server", "incursa"),
                new QPackFieldLine("x-custom", "one"),
                new QPackFieldLine("cache-control", "no-store"),
            ],
            headers);
        Assert.Equal(headers, QPackDecoder.DecodeFieldSection(encodedFieldSection));
        Assert.Single(headers, header => header.Name == ":status");
    }

    [Fact]
    public void ServerResponseBuilder_PreservesManyCustomResponseHeaderBytes()
    {
        QPackFieldLine[] responseHeaders = Enumerable.Range(0, 50)
            .Select(index => new QPackFieldLine($"x-bench-{index:00}", new string((char)('a' + (index % 26)), 32)))
            .ToArray();
        Http3ServerResponse response = new(200, ReadOnlyMemory<byte>.Empty, responseHeaders);

        IReadOnlyList<QPackFieldLine> headers = Http3Server.BuildResponseHeaders(response);
        byte[] encodedFieldSection = Http3Server.EncodeResponseFieldSection(headers);

        Assert.Equal(headers, QPackDecoder.DecodeFieldSection(encodedFieldSection));
    }

    [Theory]
    [InlineData("text/plain", "Hello, World!")]
    [InlineData("application/json", """{"message":"Hello, World!"}""")]
    public void ResponseFrames_WrappedInFinalStreamPayloadPreserveBytesAndMetadata(string contentType, string bodyText)
    {
        const ulong streamId = 0;
        byte[] body = System.Text.Encoding.UTF8.GetBytes(bodyText);
        byte[] encodedFieldSection = EncodeTechEmpowerResponseFieldSection(contentType, body.Length);
        byte[] headersFrame = Http3FrameWriter.WriteHeaders(encodedFieldSection);
        byte[] dataFrame = Http3FrameWriter.WriteData(body);
        byte[] responseFrames =
        [
            .. headersFrame,
            .. dataFrame,
        ];

        byte[] streamPayload = BuildStreamPayload(streamId, responseFrames, fin: true);

        Assert.True(QuicStreamParser.TryParseStreamFrame(streamPayload, out QuicStreamFrame streamFrame));
        Assert.Equal(streamId, streamFrame.StreamId.Value);
        Assert.True(streamFrame.IsFin);
        Assert.True(streamFrame.HasLength);
        Assert.False(streamFrame.HasOffset);
        Assert.Equal(0UL, streamFrame.Offset);
        Assert.Equal(responseFrames.Length, streamFrame.StreamDataLength);
        Assert.Equal(responseFrames, streamFrame.StreamData.ToArray());
        Assert.All(streamPayload.AsSpan(streamFrame.ConsumedLength).ToArray(), value => Assert.Equal(0, value));

        Http3Frame[] frames = new Http3FrameReader().Read(streamFrame.StreamData);
        Assert.Collection(
            frames,
            frame =>
            {
                Http3HeadersFrame headers = Assert.IsType<Http3HeadersFrame>(frame);
                Assert.Equal(headersFrame, Http3FrameWriter.WriteHeaders(headers.EncodedFieldSection.Span));
                Assert.Equal(
                    [
                        new QPackFieldLine(":status", "200"),
                        new QPackFieldLine("server", "incursa"),
                        new QPackFieldLine("date", "Wed, 27 May 2026 15:00:00 GMT"),
                        new QPackFieldLine("content-type", contentType),
                        new QPackFieldLine("content-length", body.Length.ToString()),
                    ],
                    QPackDecoder.DecodeFieldSection(headers.EncodedFieldSection));
            },
            frame =>
            {
                Http3DataFrame data = Assert.IsType<Http3DataFrame>(frame);
                Assert.Equal(dataFrame, Http3FrameWriter.WriteData(data.Data.Span));
                Assert.Equal(body, data.Data.ToArray());
            });
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
    public void FrameReader_ParsesSingleHeadersFramePayloadExactly()
    {
        byte[] fieldSection = EncodePlaintextRequestFieldSection();
        byte[] encoded = Http3FrameWriter.WriteHeaders(fieldSection);
        Http3FrameReader reader = new();

        Http3Frame[] frames = reader.Read(encoded);

        Http3HeadersFrame frame = Assert.IsType<Http3HeadersFrame>(Assert.Single(frames));
        Assert.Equal(fieldSection, frame.EncodedFieldSection.ToArray());
        Assert.Equal(fieldSection, frame.Payload);
        Assert.Equal(0, reader.PendingByteCount);
        Assert.Equal(
            BuildPlaintextRequestHeaders(),
            QPackDecoder.DecodeFieldSection(frame.EncodedFieldSection));
    }

    [Fact]
    public void FrameReader_FragmentedHeadersFramePreservesPayloadAndPendingBytes()
    {
        byte[] fieldSection = EncodePlaintextRequestFieldSection();
        byte[] encoded = Http3FrameWriter.WriteHeaders(fieldSection);
        int split = encoded.Length / 2;
        Http3FrameReader reader = new();

        Http3Frame[] firstFrames = reader.Read(encoded.AsSpan(0, split));
        int pendingAfterFirstRead = reader.PendingByteCount;
        Http3Frame[] secondFrames = reader.Read(encoded.AsSpan(split));

        Assert.Empty(firstFrames);
        Assert.Equal(split, pendingAfterFirstRead);
        Http3HeadersFrame frame = Assert.IsType<Http3HeadersFrame>(Assert.Single(secondFrames));
        Assert.Equal(fieldSection, frame.EncodedFieldSection.ToArray());
        Assert.Equal(fieldSection, frame.Payload);
        Assert.Equal(0, reader.PendingByteCount);
    }

    [Fact]
    public void FrameReader_PreservesCompleteFrameBeforePartialFrameUntilCompletion()
    {
        byte[] dataPayload = [0xAA, 0xBB];
        byte[] headersPayload = [0x00, 0x00, 0xC1];
        byte[] dataFrame = Http3FrameWriter.WriteData(dataPayload);
        byte[] headersFrame = Http3FrameWriter.WriteHeaders(headersPayload);
        int partialHeaderLength = headersFrame.Length - 1;
        byte[] firstRead =
        [
            .. dataFrame,
            .. headersFrame.AsSpan(0, partialHeaderLength),
        ];
        Http3FrameReader reader = new();

        Http3Frame[] firstFrames = reader.Read(firstRead);
        Http3Frame[] secondFrames = reader.Read(headersFrame.AsSpan(partialHeaderLength));

        Http3DataFrame data = Assert.IsType<Http3DataFrame>(Assert.Single(firstFrames));
        Assert.Equal(dataPayload, data.Data.ToArray());
        Http3HeadersFrame headers = Assert.IsType<Http3HeadersFrame>(Assert.Single(secondFrames));
        Assert.Equal(headersPayload, headers.EncodedFieldSection.ToArray());
        Assert.Equal(0, reader.PendingByteCount);
    }

    [Fact]
    public void FrameReader_PreservesUnknownReservedAndDataFrameOrdering()
    {
        byte[] unknownPayload = [0xAA, 0xBB];
        byte[] reservedPayload = [0xCC];
        byte[] dataPayload = [0xDD];
        byte[] encoded =
        [
            .. Http3FrameWriter.WriteFrame(0x41, unknownPayload),
            .. Http3FrameWriter.WriteFrame(0x21, reservedPayload),
            .. Http3FrameWriter.WriteData(dataPayload),
        ];

        Http3Frame[] frames = new Http3FrameReader().Read(encoded);

        Assert.Collection(
            frames,
            frame =>
            {
                Http3UnknownFrame unknown = Assert.IsType<Http3UnknownFrame>(frame);
                Assert.Equal(0x41UL, unknown.Type);
                Assert.False(unknown.IsReserved);
                Assert.Equal(unknownPayload, unknown.Payload);
            },
            frame =>
            {
                Http3UnknownFrame reserved = Assert.IsType<Http3UnknownFrame>(frame);
                Assert.Equal(0x21UL, reserved.Type);
                Assert.True(reserved.IsReserved);
                Assert.Equal(reservedPayload, reserved.Payload);
            },
            frame =>
            {
                Http3DataFrame data = Assert.IsType<Http3DataFrame>(frame);
                Assert.Equal(dataPayload, data.Data.ToArray());
            });
    }

    [Fact]
    public void FrameReader_TruncatedPayloadStaysPendingUntilCompletionFails()
    {
        byte[] encoded = Convert.FromHexString("00030102");
        Http3FrameReader reader = new();

        Http3Frame[] frames = reader.Read(encoded);

        Assert.Empty(frames);
        Assert.Equal(encoded.Length, reader.PendingByteCount);
        Http3Exception exception = Assert.Throws<Http3Exception>(reader.Complete);
        Assert.Equal(Http3ErrorCode.FrameError, exception.ErrorCode);
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

    private static byte[] EncodeResponseFieldSection(string contentType, int contentLength)
    {
        return QPackEncoder.EncodeFieldSection(
        [
            new QPackFieldLine(":status", "200"),
            new QPackFieldLine("content-type", contentType),
            new QPackFieldLine("content-length", contentLength.ToString()),
        ]);
    }

    private static byte[] EncodeTechEmpowerResponseFieldSection(string contentType, int contentLength)
    {
        return QPackEncoder.EncodeFieldSection(
        [
            new QPackFieldLine(":status", "200"),
            .. BuildTechEmpowerResponseHeaders(contentType, contentLength),
        ]);
    }

    private static QPackFieldLine[] BuildTechEmpowerResponseHeaders(string contentType, int contentLength)
    {
        return
        [
            new QPackFieldLine("server", "incursa"),
            new QPackFieldLine("date", "Wed, 27 May 2026 15:00:00 GMT"),
            new QPackFieldLine("content-type", contentType),
            new QPackFieldLine("content-length", contentLength.ToString()),
        ];
    }

    private static QPackFieldLine[] BuildPlaintextRequestHeaders()
    {
        return
        [
            new QPackFieldLine(":method", "GET"),
            new QPackFieldLine(":scheme", "https"),
            new QPackFieldLine(":authority", "localhost:5444"),
            new QPackFieldLine(":path", "/plaintext"),
            new QPackFieldLine("user-agent", "h2load"),
            new QPackFieldLine("accept", "*/*"),
        ];
    }

    private static byte[] EncodePlaintextRequestFieldSection()
    {
        return QPackEncoder.EncodeFieldSection(BuildPlaintextRequestHeaders());
    }

    private static byte[] BuildStreamPayload(ulong streamId, ReadOnlySpan<byte> streamData, bool fin)
    {
        byte frameType = QuicStreamFrameBits.StreamFrameTypeMinimum | QuicStreamFrameBits.LengthBitMask;
        if (fin)
        {
            frameType |= QuicStreamFrameBits.FinBitMask;
        }

        int bufferLength = Math.Max(
            QuicInitialPacketProtection.HeaderProtectionSampleOffset + QuicInitialPacketProtection.HeaderProtectionSampleLength,
            streamData.Length + 32);
        byte[] buffer = new byte[bufferLength];
        Assert.True(QuicFrameCodec.TryFormatStreamFrame(frameType, streamId, 0, streamData, buffer, out int frameBytesWritten));
        buffer.AsSpan(frameBytesWritten).Fill(0);
        return buffer;
    }
}
