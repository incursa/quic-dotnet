namespace Incursa.Quic.Tests;

public sealed class QPackInstructionStreamTests
{
    private const string RfcAppendixB2EncoderStreamHex =
        "3FBD01C00F7777772E6578616D706C652E636F6DC10C2F73616D706C652F70617468";

    private const string RfcAppendixB3LiteralInsertHex =
        "4A637573746F6D2D6B65790C637573746F6D2D76616C7565";

    private const string RfcAppendixB4DuplicateHex = "02";

    private const string RfcAppendixB5DynamicNameInsertHex = "810D637573746F6D2D76616C756532";

    [Fact]
    public void EncoderStreamParser_ParsesSetDynamicTableCapacityAcrossPartialBuffers()
    {
        QPackDecoder decoder = new(maximumDynamicTableCapacity: 220, maximumBlockedStreams: 1);

        Assert.Empty(decoder.DecodeEncoderStream(Convert.FromHexString("3F")));
        Assert.Equal(0, decoder.DynamicTable.Capacity);

        Assert.Empty(decoder.DecodeEncoderStream(Convert.FromHexString("BD01")));

        Assert.Equal(220, decoder.DynamicTable.Capacity);
    }

    [Fact]
    public void EncoderStreamParser_ParsesInsertWithStaticNameReference()
    {
        QPackDecoder decoder = new(maximumDynamicTableCapacity: 220, maximumBlockedStreams: 1);
        decoder.DecodeEncoderStream(Convert.FromHexString("3FBD01"));

        decoder.DecodeEncoderStream(Convert.FromHexString("C00F7777772E6578616D706C652E636F6D"));

        Assert.True(decoder.DynamicTable.TryGetByAbsoluteIndex(0, out QPackDynamicTableEntry entry));
        Assert.Equal(new QPackFieldLine(":authority", "www.example.com"), entry.FieldLine);
    }

    [Fact]
    public void EncoderStreamParser_ParsesInsertWithDynamicNameReference()
    {
        QPackDecoder decoder = CreateDecoderWithAppendixB4Table();

        decoder.DecodeEncoderStream(Convert.FromHexString(RfcAppendixB5DynamicNameInsertHex));

        Assert.True(decoder.DynamicTable.TryGetByAbsoluteIndex(4, out QPackDynamicTableEntry entry));
        Assert.Equal(new QPackFieldLine("custom-key", "custom-value2"), entry.FieldLine);
    }

    [Fact]
    public void EncoderStreamParser_ParsesInsertWithLiteralNameAcrossPartialBuffers()
    {
        QPackDecoder decoder = new(maximumDynamicTableCapacity: 220, maximumBlockedStreams: 1);
        decoder.DecodeEncoderStream(Convert.FromHexString("3FBD01"));

        Assert.Empty(decoder.DecodeEncoderStream(Convert.FromHexString("4A637573746F6D2D6B65790C637573")));
        Assert.Equal(0UL, decoder.DynamicTable.InsertCount);

        decoder.DecodeEncoderStream(Convert.FromHexString("746F6D2D76616C7565"));

        Assert.True(decoder.DynamicTable.TryGetByAbsoluteIndex(0, out QPackDynamicTableEntry entry));
        Assert.Equal(new QPackFieldLine("custom-key", "custom-value"), entry.FieldLine);
    }

    [Fact]
    public void EncoderStreamParser_ParsesDuplicate()
    {
        QPackDecoder decoder = CreateDecoderWithAppendixB3Table();

        decoder.DecodeEncoderStream(Convert.FromHexString(RfcAppendixB4DuplicateHex));

        Assert.True(decoder.DynamicTable.TryGetByAbsoluteIndex(0, out QPackDynamicTableEntry original));
        Assert.True(decoder.DynamicTable.TryGetByAbsoluteIndex(3, out QPackDynamicTableEntry duplicate));
        Assert.Equal(original.FieldLine, duplicate.FieldLine);
    }

    [Fact]
    public void EncoderStreamParser_RejectsPartialInstructionAtEndOfStream()
    {
        QPackDecoder decoder = new(maximumDynamicTableCapacity: 220, maximumBlockedStreams: 1);
        decoder.DecodeEncoderStream(Convert.FromHexString("3F"));

        QPackException exception = Assert.Throws<QPackException>(decoder.CompleteEncoderStream);

        Assert.Equal(QPackErrorCode.EncoderStreamError, exception.ErrorCode);
    }

    [Fact]
    public void EncoderStreamParser_RejectsMalformedIntegerDeterministically()
    {
        QPackDecoder decoder = new(maximumDynamicTableCapacity: 220, maximumBlockedStreams: 1);

        QPackException exception = Assert.Throws<QPackException>(
            () => decoder.DecodeEncoderStream(Convert.FromHexString("3FFFFFFFFFFFFFFFFFFFFF7F")));

        Assert.Equal(QPackErrorCode.EncoderStreamError, exception.ErrorCode);
    }

    [Fact]
    public void EncoderStreamParser_RejectsMalformedHuffmanLiteralWithEncoderStreamError()
    {
        QPackDecoder decoder = new(maximumDynamicTableCapacity: 220, maximumBlockedStreams: 1);
        decoder.DecodeEncoderStream(Convert.FromHexString("3FBD01"));

        QPackException exception = Assert.Throws<QPackException>(() => decoder.DecodeEncoderStream(Convert.FromHexString("6100")));

        Assert.Equal(QPackErrorCode.EncoderStreamError, exception.ErrorCode);
    }

    [Fact]
    public void DecoderStreamParser_ParsesSectionAcknowledgmentAcrossPartialBuffers()
    {
        QPackEncoder encoder = CreateEncoderWithBlockedSection(streamId: 132);

        encoder.DecodeDecoderStream(Convert.FromHexString("FF"));
        Assert.Equal(0UL, encoder.KnownReceivedCount);

        encoder.DecodeDecoderStream(Convert.FromHexString("05"));

        Assert.Equal(2UL, encoder.KnownReceivedCount);
    }

    [Fact]
    public void DecoderStreamParser_ParsesStreamCancellation()
    {
        QPackEncoder encoder = CreateEncoderWithBlockedSection(streamId: 4);

        encoder.DecodeDecoderStream(Convert.FromHexString("44"));
        encoder.DecodeDecoderStream(Convert.FromHexString("02"));

        Assert.Equal(2UL, encoder.KnownReceivedCount);
    }

    [Fact]
    public void DecoderStreamParser_ParsesInsertCountIncrement()
    {
        QPackEncoder encoder = CreateEncoderWithTwoInsertedEntries();

        encoder.DecodeDecoderStream(Convert.FromHexString("02"));

        Assert.Equal(2UL, encoder.KnownReceivedCount);
    }

    [Fact]
    public void DecoderStreamParser_RejectsPartialInstructionAtEndOfStream()
    {
        QPackEncoder encoder = CreateEncoderWithBlockedSection(streamId: 132);
        encoder.DecodeDecoderStream(Convert.FromHexString("FF"));

        QPackException exception = Assert.Throws<QPackException>(encoder.CompleteDecoderStream);

        Assert.Equal(QPackErrorCode.DecoderStreamError, exception.ErrorCode);
    }

    [Fact]
    public void DecoderStreamParser_RejectsMalformedIntegerDeterministically()
    {
        QPackEncoder encoder = CreateEncoderWithTwoInsertedEntries();

        QPackException exception = Assert.Throws<QPackException>(
            () => encoder.DecodeDecoderStream(Convert.FromHexString("3FFFFFFFFFFFFFFFFFFFFF7F")));

        Assert.Equal(QPackErrorCode.DecoderStreamError, exception.ErrorCode);
    }

    [Fact]
    public void InstructionStreams_SynchronizeEncoderAndDecoderDynamicState()
    {
        QPackEncoder encoder = new(maximumDynamicTableCapacity: 220, maximumBlockedStreams: 1);
        QPackDecoder decoder = new(maximumDynamicTableCapacity: 220, maximumBlockedStreams: 1);

        Assert.True(encoder.TrySetDynamicTableCapacity(220, out byte[] capacity));
        Assert.True(encoder.TryInsert(new QPackFieldLine(":authority", "www.example.com"), out byte[] authority));
        Assert.True(encoder.TryInsert(new QPackFieldLine(":path", "/sample/path"), out byte[] path));

        decoder.DecodeEncoderStream(capacity);
        decoder.DecodeEncoderStream(authority);
        decoder.DecodeEncoderStream(path);

        QPackFieldSectionEncodeResult encoded = encoder.EncodeFieldSection(
            4,
            [
                new QPackFieldLine(":authority", "www.example.com"),
                new QPackFieldLine(":path", "/sample/path"),
            ]);

        QPackFieldSectionDecodeResult decoded = decoder.DecodeFieldSection(4, encoded.EncodedFieldSection);

        Assert.False(decoded.IsBlocked);
        Assert.Equal(2UL, decoded.RequiredInsertCount);
        Assert.Equal(2UL, decoder.DynamicTable.InsertCount);

        encoder.DecodeDecoderStream(Convert.FromHexString("84"));

        Assert.Equal(2UL, encoder.KnownReceivedCount);
    }

    private static QPackDecoder CreateDecoderWithAppendixB3Table()
    {
        QPackDecoder decoder = new(maximumDynamicTableCapacity: 220, maximumBlockedStreams: 1);
        decoder.DecodeEncoderStream(Convert.FromHexString(RfcAppendixB2EncoderStreamHex));
        decoder.DecodeEncoderStream(Convert.FromHexString(RfcAppendixB3LiteralInsertHex));
        return decoder;
    }

    private static QPackDecoder CreateDecoderWithAppendixB4Table()
    {
        QPackDecoder decoder = CreateDecoderWithAppendixB3Table();
        decoder.DecodeEncoderStream(Convert.FromHexString(RfcAppendixB4DuplicateHex));
        return decoder;
    }

    private static QPackEncoder CreateEncoderWithTwoInsertedEntries()
    {
        QPackEncoder encoder = new(maximumDynamicTableCapacity: 220, maximumBlockedStreams: 1);
        Assert.True(encoder.TrySetDynamicTableCapacity(220, out _));
        Assert.True(encoder.TryInsert(new QPackFieldLine(":authority", "www.example.com"), out _));
        Assert.True(encoder.TryInsert(new QPackFieldLine(":path", "/sample/path"), out _));
        return encoder;
    }

    private static QPackEncoder CreateEncoderWithBlockedSection(ulong streamId = 4)
    {
        QPackEncoder encoder = CreateEncoderWithTwoInsertedEntries();
        QPackFieldSectionEncodeResult encoded = encoder.EncodeFieldSection(
            streamId,
            [
                new QPackFieldLine(":authority", "www.example.com"),
                new QPackFieldLine(":path", "/sample/path"),
            ]);
        Assert.Equal(2UL, encoded.RequiredInsertCount);
        return encoder;
    }
}
