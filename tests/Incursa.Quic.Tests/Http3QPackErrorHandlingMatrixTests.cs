using System.Text;

namespace Incursa.Quic.Tests;

public sealed class Http3QPackErrorHandlingMatrixTests
{
    [Fact]
    public void ControlStream_DataFrame_ThrowsFrameUnexpected()
    {
        Http3StreamDispatcher dispatcher = CreateServerDispatcherWithClientControlStream();
        dispatcher.ReceiveFrame(2, ReadFrame(Http3FrameWriter.WriteSettings([])));

        Http3Exception exception = Assert.Throws<Http3Exception>(
            () => dispatcher.ReceiveFrame(2, ReadFrame(Http3FrameWriter.WriteData([0x01]))));

        Assert.Equal(Http3ErrorCode.FrameUnexpected, exception.ErrorCode);
    }

    [Fact]
    public void ControlStream_HeadersFrame_ThrowsFrameUnexpected()
    {
        Http3StreamDispatcher dispatcher = CreateServerDispatcherWithClientControlStream();
        dispatcher.ReceiveFrame(2, ReadFrame(Http3FrameWriter.WriteSettings([])));

        Http3Exception exception = Assert.Throws<Http3Exception>(
            () => dispatcher.ReceiveFrame(2, ReadFrame(Http3FrameWriter.WriteHeaders([0x00]))));

        Assert.Equal(Http3ErrorCode.FrameUnexpected, exception.ErrorCode);
    }

    [Fact]
    public void ControlStream_SettingsNotFirst_ThrowsMissingSettings()
    {
        Http3StreamDispatcher dispatcher = CreateServerDispatcherWithClientControlStream();

        Http3Exception exception = Assert.Throws<Http3Exception>(
            () => dispatcher.ReceiveFrame(2, ReadFrame(Http3FrameWriter.WriteGoAway(0))));

        Assert.Equal(Http3ErrorCode.MissingSettings, exception.ErrorCode);
    }

    [Fact]
    public void SettingsFrame_DuplicateParameter_ThrowsSettingsError()
    {
        byte[] encoded = Http3FrameWriter.WriteFrame((ulong)Http3FrameType.Settings, [0x06, 0x01, 0x06, 0x02]);

        Http3Exception exception = Assert.Throws<Http3Exception>(() => ReadFrame(encoded));

        Assert.Equal(Http3ErrorCode.SettingsError, exception.ErrorCode);
    }

    [Fact]
    public void ControlStream_DuplicateControlStream_ThrowsStreamCreationError()
    {
        Http3StreamDispatcher dispatcher = new(Http3EndpointRole.Server);
        dispatcher.RegisterUnidirectionalStream(2);
        dispatcher.ReceiveUnidirectionalStreamTypeBytes(2, [0x00]);
        dispatcher.RegisterUnidirectionalStream(6);

        Http3Exception exception = Assert.Throws<Http3Exception>(
            () => dispatcher.ReceiveUnidirectionalStreamTypeBytes(6, [0x00]));

        Assert.Equal(Http3ErrorCode.StreamCreationError, exception.ErrorCode);
    }

    [Fact]
    public void BidirectionalStream_ServerInitiated_ThrowsStreamCreationError()
    {
        Http3StreamDispatcher dispatcher = new(Http3EndpointRole.Client);

        Http3Exception exception = Assert.Throws<Http3Exception>(() => dispatcher.RegisterBidirectionalStream(1));

        Assert.Equal(Http3ErrorCode.StreamCreationError, exception.ErrorCode);
    }

    [Fact]
    public void UnidirectionalStream_ClientInitiatedPushStream_ThrowsStreamCreationError()
    {
        Http3StreamDispatcher dispatcher = new(Http3EndpointRole.Server, enableServerPush: true);
        dispatcher.RegisterUnidirectionalStream(2);

        Http3Exception exception = Assert.Throws<Http3Exception>(
            () => dispatcher.ReceiveUnidirectionalStreamTypeBytes(2, [(byte)Http3StreamType.Push]));

        Assert.Equal(Http3ErrorCode.StreamCreationError, exception.ErrorCode);
    }

    [Fact]
    public void QPackFieldSection_InvalidStaticIndex_ThrowsDecompressionFailed()
    {
        byte[] encoded = [0x00, 0x00, .. QPackInteger.Encode(99, 6, 0xC0)];

        QPackException exception = Assert.Throws<QPackException>(() => QPackDecoder.DecodeFieldSection(encoded));

        Assert.Equal(QPackErrorCode.DecompressionFailed, exception.ErrorCode);
    }

    [Fact]
    public void QPackFieldSection_InvalidDynamicReference_ThrowsDecompressionFailed()
    {
        QPackDecoder decoder = new(maximumDynamicTableCapacity: 220, maximumBlockedStreams: 1);
        decoder.DecodeEncoderStream(Convert.FromHexString("3FBD01C00F7777772E6578616D706C652E636F6D"));

        QPackException exception = Assert.Throws<QPackException>(
            () => decoder.DecodeFieldSection(8, Convert.FromHexString("020180")));

        Assert.Equal(QPackErrorCode.DecompressionFailed, exception.ErrorCode);
    }

    [Fact]
    public void QPackEncoderStream_DynamicNameReferenceToEvictedEntry_ThrowsEncoderStreamError()
    {
        QPackDecoder decoder = new(maximumDynamicTableCapacity: 96, maximumBlockedStreams: 0);

        decoder.DecodeEncoderStream(QPackInteger.Encode(96, 5, 0x20));
        decoder.DecodeEncoderStream(EncodeInsertWithLiteralName("x-name", "a"));
        decoder.DecodeEncoderStream(EncodeInsertWithLiteralName("large-name", new string('b', 48)));
        Assert.False(decoder.DynamicTable.TryGetByAbsoluteIndex(0, out _));

        byte[] referenceEvictedEntryAsName = [.. QPackInteger.Encode(1, 6, 0x80), 0x01, (byte)'z'];
        QPackException exception = Assert.Throws<QPackException>(
            () => decoder.DecodeEncoderStream(referenceEvictedEntryAsName));

        Assert.Equal(QPackErrorCode.EncoderStreamError, exception.ErrorCode);
    }

    [Fact]
    public void FrameReader_TruncatedFrame_ThrowsFrameError()
    {
        Http3FrameReader reader = new();
        Assert.Empty(reader.Read(Convert.FromHexString("00030102")));

        Http3Exception exception = Assert.Throws<Http3Exception>(reader.Complete);

        Assert.Equal(Http3ErrorCode.FrameError, exception.ErrorCode);
    }

    [Fact]
    public void FrameReader_ExtraPayloadBytes_ThrowsFrameError()
    {
        byte[] encoded = Convert.FromHexString("03020102");

        Http3Exception exception = Assert.Throws<Http3Exception>(() => ReadFrame(encoded));

        Assert.Equal(Http3ErrorCode.FrameError, exception.ErrorCode);
    }

    [Fact]
    public void HeaderValidator_InvalidContentLength_ThrowsMessageError()
    {
        Http3RequestMessageValidator validator = new();
        validator.ReceiveHeaders(
        [
            .. CommonRequestHeaders(),
            new QPackFieldLine("content-length", "5"),
        ]);
        validator.ReceiveData(4);

        Http3Exception exception = Assert.Throws<Http3Exception>(validator.Complete);

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }

    [Fact]
    public void HeaderValidator_ResponseMissingStatus_ThrowsMessageError()
    {
        Http3Exception exception = Assert.Throws<Http3Exception>(
            () => Http3HeaderValidator.ValidateResponseHeaders([new QPackFieldLine("server", "incursa")]));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }

    [Fact]
    public void HeaderValidator_RequestMissingPseudoHeader_ThrowsMessageError()
    {
        QPackFieldLine[] headers = [.. CommonRequestHeaders().Where(header => header.Name != ":path")];

        Http3Exception exception = Assert.Throws<Http3Exception>(() => Http3HeaderValidator.ValidateRequestHeaders(headers));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }

    [Fact]
    public void HeaderValidator_UppercaseHeaderName_ThrowsMessageError()
    {
        QPackFieldLine[] headers = [.. CommonRequestHeaders(), new QPackFieldLine("Host", "example.com")];

        Http3Exception exception = Assert.Throws<Http3Exception>(() => Http3HeaderValidator.ValidateRequestHeaders(headers));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }

    [Fact]
    public void HeaderValidator_PseudoHeaderAfterRegularHeader_ThrowsMessageError()
    {
        QPackFieldLine[] headers = [new QPackFieldLine("server", "incursa"), new QPackFieldLine(":status", "200")];

        Http3Exception exception = Assert.Throws<Http3Exception>(() => Http3HeaderValidator.ValidateResponseHeaders(headers));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }

    private static Http3StreamDispatcher CreateServerDispatcherWithClientControlStream()
    {
        Http3StreamDispatcher dispatcher = new(Http3EndpointRole.Server);
        dispatcher.RegisterUnidirectionalStream(2);
        dispatcher.ReceiveUnidirectionalStreamTypeBytes(2, [0x00]);
        return dispatcher;
    }

    private static Http3Frame ReadFrame(byte[] encoded)
    {
        return Assert.Single(new Http3FrameReader().Read(encoded));
    }

    private static byte[] EncodeInsertWithLiteralName(string name, string value)
    {
        return [.. EncodeStringLiteral(name, 6, 0x40), .. EncodeStringLiteral(value, 8)];
    }

    private static byte[] EncodeStringLiteral(string value, int prefixBitCount, byte prefixBits = 0)
    {
        byte[] bytes = Encoding.Latin1.GetBytes(value);
        return [.. QPackInteger.Encode((ulong)bytes.Length, prefixBitCount - 1, prefixBits), .. bytes];
    }

    private static QPackFieldLine[] CommonRequestHeaders()
    {
        return
        [
            new QPackFieldLine(":method", "GET"),
            new QPackFieldLine(":scheme", "https"),
            new QPackFieldLine(":authority", "example.com"),
            new QPackFieldLine(":path", "/"),
        ];
    }
}
