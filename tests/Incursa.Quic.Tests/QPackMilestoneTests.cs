namespace Incursa.Quic.Tests;

public sealed class QPackMilestoneTests
{
    private const string RfcAppendixB2EncoderStreamHex =
        "3FBD01C00F7777772E6578616D706C652E636F6DC10C2F73616D706C652F70617468";

    private const string RfcAppendixB3EncoderStreamHex =
        "4A637573746F6D2D6B65790C637573746F6D2D76616C7565";

    private const string RfcAppendixB4DuplicateInstructionHex = "02";

    private const string RfcAppendixB5EvictingInsertHex = "810D637573746F6D2D76616C756532";

    [Theory]
    [InlineData(0UL, 5, "00")]
    [InlineData(10UL, 5, "0A")]
    [InlineData(30UL, 5, "1E")]
    [InlineData(31UL, 5, "1F00")]
    [InlineData(1337UL, 5, "1F9A0A")]
    [InlineData(QPackInteger.MaxValue, 8, "FF80FEFFFFFFFFFFFF3F")]
    public void PrefixedInteger_RoundTripsBoundaryAndMultibyteValues(ulong value, int prefixBitCount, string expectedHex)
    {
        byte[] encoded = QPackInteger.Encode(value, prefixBitCount);

        Assert.Equal(expectedHex, Convert.ToHexString(encoded));
        ulong decoded = QPackInteger.Decode(encoded, prefixBitCount, out int bytesConsumed);
        Assert.Equal(value, decoded);
        Assert.Equal(encoded.Length, bytesConsumed);
    }

    [Fact]
    public void StaticTable_ContainsRfc9204Entries()
    {
        Assert.Equal(99, QPackStaticTable.Count);
        Assert.True(QPackStaticTable.TryGet(0, out QPackFieldLine authority));
        Assert.Equal(new QPackFieldLine(":authority", ""), authority);
        Assert.True(QPackStaticTable.TryGet(98, out QPackFieldLine sameOrigin));
        Assert.Equal(new QPackFieldLine("x-frame-options", "sameorigin"), sameOrigin);
        Assert.False(QPackStaticTable.TryGet(99, out _));
    }

    [Fact]
    public void DecodeFieldSection_DecodesRfc9204AppendixB1LiteralWithStaticNameReference()
    {
        byte[] encoded = Convert.FromHexString("0000510B2F696E6465782E68746D6C");

        QPackFieldLine[] decoded = QPackDecoder.DecodeFieldSection(encoded);

        QPackFieldLine field = Assert.Single(decoded);
        Assert.Equal(new QPackFieldLine(":path", "/index.html"), field);
    }

    [Fact]
    public void EncodeFieldSection_ProducesRfc9204AppendixB1StaticNameReferenceForPathLiteral()
    {
        byte[] encoded = QPackEncoder.EncodeFieldSection(
        [
            new QPackFieldLine(":path", "/index.html"),
        ]);

        Assert.Equal("0000510B2F696E6465782E68746D6C", Convert.ToHexString(encoded));
    }

    [Fact]
    public void EncodeFieldSection_UsesStaticIndexedFieldForExactStaticMatch()
    {
        byte[] encoded = QPackEncoder.EncodeFieldSection(
        [
            new QPackFieldLine(":path", "/"),
        ]);

        Assert.Equal("0000C1", Convert.ToHexString(encoded));
        QPackFieldLine field = Assert.Single(QPackDecoder.DecodeFieldSection(encoded));
        Assert.Equal(new QPackFieldLine(":path", "/"), field);
    }

    [Fact]
    public void DecodeFieldSection_DecodesLiteralFieldLineWithLiteralName()
    {
        byte[] encoded = QPackEncoder.EncodeFieldSection(
        [
            new QPackFieldLine("custom-key", "custom-value"),
        ]);

        Assert.Equal("00002703637573746F6D2D6B65790C637573746F6D2D76616C7565", Convert.ToHexString(encoded));
        QPackFieldLine field = Assert.Single(QPackDecoder.DecodeFieldSection(encoded));
        Assert.Equal(new QPackFieldLine("custom-key", "custom-value"), field);
    }

    [Fact]
    public void DecodeFieldSection_PreservesFieldOrderAndDuplicates()
    {
        QPackFieldLine[] fields =
        [
            new QPackFieldLine("set-cookie", "a=1"),
            new QPackFieldLine(":status", "200"),
            new QPackFieldLine("set-cookie", "b=2"),
        ];

        QPackFieldLine[] decoded = QPackDecoder.DecodeFieldSection(QPackEncoder.EncodeFieldSection(fields));

        Assert.Equal(fields, decoded);
    }

    [Fact]
    public void DecodeFieldSection_RejectsInvalidStaticTableIndexWithDecompressionFailed()
    {
        byte[] encoded = Convert.FromHexString("0000FF24");

        QPackException exception = Assert.Throws<QPackException>(() => QPackDecoder.DecodeFieldSection(encoded));
        Assert.Equal(QPackErrorCode.DecompressionFailed, exception.ErrorCode);
    }

    [Fact]
    public void DecodeFieldSection_RejectsDynamicTableReferencesWithDecompressionFailed()
    {
        byte[] encoded = Convert.FromHexString("000080");

        QPackException exception = Assert.Throws<QPackException>(() => QPackDecoder.DecodeFieldSection(encoded));
        Assert.Equal(QPackErrorCode.DecompressionFailed, exception.ErrorCode);
    }

    [Fact]
    public void EncodeFieldSection_IsDeterministicForCommonHttp3Request()
    {
        QPackFieldLine[] fields =
        [
            new QPackFieldLine(":method", "GET"),
            new QPackFieldLine(":scheme", "https"),
            new QPackFieldLine(":authority", "example.com"),
            new QPackFieldLine(":path", "/index.html"),
            new QPackFieldLine("user-agent", "incursa-test"),
        ];

        byte[] first = QPackEncoder.EncodeFieldSection(fields);
        byte[] second = QPackEncoder.EncodeFieldSection(fields);

        Assert.Equal(first, second);
        Assert.Equal(fields, QPackDecoder.DecodeFieldSection(first));
    }

    [Fact]
    public void EncodeFieldSection_RoundTripsCommonHttp3Response()
    {
        QPackFieldLine[] fields =
        [
            new QPackFieldLine(":status", "200"),
            new QPackFieldLine("content-type", "text/plain"),
            new QPackFieldLine("content-length", "5"),
            new QPackFieldLine("server", "incursa"),
            new QPackFieldLine("cache-control", "no-cache"),
        ];

        byte[] encoded = QPackEncoder.EncodeFieldSection(fields);
        QPackFieldLine[] decoded = QPackDecoder.DecodeFieldSection(encoded);

        Assert.Equal(fields, decoded);
    }

    [Fact]
    public void DynamicTable_StartsWithZeroCapacityAndUsesRfcEntrySize()
    {
        QPackDynamicTable table = new(maximumCapacity: 220);

        Assert.Equal(0, table.Capacity);
        Assert.Equal(0, table.CurrentSize);
        Assert.Equal(0UL, table.InsertCount);
        Assert.Equal(57, QPackDynamicTable.GetEntrySize(new QPackFieldLine(":authority", "www.example.com")));
        Assert.False(table.TryInsert(new QPackFieldLine(":authority", "www.example.com"), out _));
    }

    [Fact]
    public void DynamicTable_AllowsDuplicateEntries()
    {
        QPackDecoder decoder = new(maximumDynamicTableCapacity: 220, maximumBlockedStreams: 1);
        decoder.DecodeEncoderStream(Convert.FromHexString(RfcAppendixB2EncoderStreamHex));
        decoder.DecodeEncoderStream(Convert.FromHexString(RfcAppendixB3EncoderStreamHex));

        decoder.DecodeEncoderStream(Convert.FromHexString(RfcAppendixB4DuplicateInstructionHex));

        Assert.Equal(4UL, decoder.DynamicTable.InsertCount);
        Assert.True(decoder.DynamicTable.TryGetByAbsoluteIndex(0, out QPackDynamicTableEntry original));
        Assert.True(decoder.DynamicTable.TryGetByAbsoluteIndex(3, out QPackDynamicTableEntry duplicate));
        Assert.Equal(original.FieldLine, duplicate.FieldLine);
    }

    [Fact]
    public void DynamicTable_EvictsOldestEntriesWhenCapacityRequiresIt()
    {
        QPackDecoder decoder = new(maximumDynamicTableCapacity: 220, maximumBlockedStreams: 1);
        decoder.DecodeEncoderStream(Convert.FromHexString(RfcAppendixB2EncoderStreamHex));
        decoder.DecodeEncoderStream(Convert.FromHexString(RfcAppendixB3EncoderStreamHex));
        decoder.DecodeEncoderStream(Convert.FromHexString(RfcAppendixB4DuplicateInstructionHex));

        decoder.DecodeEncoderStream(Convert.FromHexString(RfcAppendixB5EvictingInsertHex));

        Assert.Equal(5UL, decoder.DynamicTable.InsertCount);
        Assert.Equal(1UL, decoder.DynamicTable.DroppedCount);
        Assert.Equal(215, decoder.DynamicTable.CurrentSize);
        Assert.False(decoder.DynamicTable.TryGetByAbsoluteIndex(0, out _));
        Assert.True(decoder.DynamicTable.TryGetByAbsoluteIndex(4, out QPackDynamicTableEntry inserted));
        Assert.Equal(new QPackFieldLine("custom-key", "custom-value2"), inserted.FieldLine);
    }

    [Fact]
    public void DecodeFieldSection_BlocksWhenFieldSectionArrivesBeforeEncoderInstructions()
    {
        QPackDecoder decoder = new(maximumDynamicTableCapacity: 220, maximumBlockedStreams: 1);
        byte[] encodedFieldSection = Convert.FromHexString("03811011");

        QPackFieldSectionDecodeResult blocked = decoder.DecodeFieldSection(4, encodedFieldSection);

        Assert.True(blocked.IsBlocked);
        Assert.Equal(2UL, blocked.RequiredInsertCount);
        Assert.Equal(1, decoder.BlockedStreamCount);
    }

    [Fact]
    public void DecodeEncoderStream_UnblocksFieldSectionAfterMissingEntriesArrive()
    {
        QPackDecoder decoder = new(maximumDynamicTableCapacity: 220, maximumBlockedStreams: 1);
        decoder.DecodeFieldSection(4, Convert.FromHexString("03811011"));

        QPackFieldSectionDecodeResult[] unblocked =
            decoder.DecodeEncoderStream(Convert.FromHexString(RfcAppendixB2EncoderStreamHex));

        QPackFieldSectionDecodeResult result = Assert.Single(unblocked);
        Assert.False(result.IsBlocked);
        Assert.Equal(4UL, result.StreamId);
        Assert.Equal(
            [
                new QPackFieldLine(":authority", "www.example.com"),
                new QPackFieldLine(":path", "/sample/path"),
            ],
            result.FieldLines);
        Assert.Equal(0, decoder.BlockedStreamCount);
    }

    [Fact]
    public void DecodeFieldSection_DecodesDynamicRelativeReferences()
    {
        QPackDecoder decoder = new(maximumDynamicTableCapacity: 220, maximumBlockedStreams: 1);
        decoder.DecodeEncoderStream(Convert.FromHexString(RfcAppendixB2EncoderStreamHex));
        decoder.DecodeEncoderStream(Convert.FromHexString(RfcAppendixB3EncoderStreamHex));
        decoder.DecodeEncoderStream(Convert.FromHexString(RfcAppendixB4DuplicateInstructionHex));

        QPackFieldSectionDecodeResult result = decoder.DecodeFieldSection(8, Convert.FromHexString("050080C181"));

        Assert.False(result.IsBlocked);
        Assert.Equal(
            [
                new QPackFieldLine(":authority", "www.example.com"),
                new QPackFieldLine(":path", "/"),
                new QPackFieldLine("custom-key", "custom-value"),
            ],
            result.FieldLines);
    }

    [Fact]
    public void DecodeFieldSection_RejectsInvalidDynamicReferenceWithDecompressionFailed()
    {
        QPackDecoder decoder = new(maximumDynamicTableCapacity: 220, maximumBlockedStreams: 1);
        decoder.DecodeEncoderStream(Convert.FromHexString(RfcAppendixB2EncoderStreamHex));

        QPackException exception =
            Assert.Throws<QPackException>(() => decoder.DecodeFieldSection(8, Convert.FromHexString("020180")));

        Assert.Equal(QPackErrorCode.DecompressionFailed, exception.ErrorCode);
    }

    [Fact]
    public void DecodeEncoderStream_RejectsInvalidDynamicInstructionReferenceWithEncoderStreamError()
    {
        QPackDecoder decoder = new(maximumDynamicTableCapacity: 220, maximumBlockedStreams: 1);

        QPackException exception =
            Assert.Throws<QPackException>(() => decoder.DecodeEncoderStream(Convert.FromHexString("00")));

        Assert.Equal(QPackErrorCode.EncoderStreamError, exception.ErrorCode);
    }

    [Fact]
    public void DecodeFieldSection_RejectsMoreBlockedStreamsThanConfigured()
    {
        QPackDecoder decoder = new(maximumDynamicTableCapacity: 220, maximumBlockedStreams: 1);
        byte[] encodedFieldSection = Convert.FromHexString("03811011");

        decoder.DecodeFieldSection(4, encodedFieldSection);
        QPackException exception = Assert.Throws<QPackException>(() => decoder.DecodeFieldSection(8, encodedFieldSection));

        Assert.Equal(QPackErrorCode.DecompressionFailed, exception.ErrorCode);
    }

    [Fact]
    public void Encoder_EmitsRfcAppendixB2CapacityAndInsertInstructions()
    {
        QPackEncoder encoder = new(maximumDynamicTableCapacity: 220, maximumBlockedStreams: 1);

        Assert.True(encoder.TrySetDynamicTableCapacity(220, out byte[] capacityInstruction));
        Assert.True(encoder.TryInsert(new QPackFieldLine(":authority", "www.example.com"), out byte[] authorityInstruction));
        Assert.True(encoder.TryInsert(new QPackFieldLine(":path", "/sample/path"), out byte[] pathInstruction));

        Assert.Equal("3FBD01", Convert.ToHexString(capacityInstruction));
        Assert.Equal("C00F7777772E6578616D706C652E636F6D", Convert.ToHexString(authorityInstruction));
        Assert.Equal("C10C2F73616D706C652F70617468", Convert.ToHexString(pathInstruction));
        Assert.Equal(106, encoder.DynamicTable.CurrentSize);
    }

    [Fact]
    public void Encoder_DoesNotInsertEntryLargerThanCurrentCapacity()
    {
        QPackEncoder encoder = new(maximumDynamicTableCapacity: 220, maximumBlockedStreams: 1);
        Assert.True(encoder.TrySetDynamicTableCapacity(40, out _));

        Assert.False(encoder.TryInsert(new QPackFieldLine(":authority", "www.example.com"), out byte[] instruction));

        Assert.Empty(instruction);
        Assert.Equal(0UL, encoder.DynamicTable.InsertCount);
    }

    [Fact]
    public void Encoder_DoesNotEvictEntriesThatAreNotEvictable()
    {
        QPackEncoder encoder = new(maximumDynamicTableCapacity: 106, maximumBlockedStreams: 1);
        Assert.True(encoder.TrySetDynamicTableCapacity(106, out _));
        Assert.True(encoder.TryInsert(new QPackFieldLine(":authority", "www.example.com"), out _));
        Assert.True(encoder.TryInsert(new QPackFieldLine(":path", "/sample/path"), out _));

        Assert.False(encoder.TryInsert(new QPackFieldLine("custom-key", "custom-value"), out _));

        Assert.Equal(2UL, encoder.DynamicTable.InsertCount);
        Assert.Equal(106, encoder.DynamicTable.CurrentSize);
    }

    [Fact]
    public void Encoder_EvictsEntriesAfterDecoderAcknowledgesInsertCount()
    {
        QPackEncoder encoder = new(maximumDynamicTableCapacity: 106, maximumBlockedStreams: 1);
        Assert.True(encoder.TrySetDynamicTableCapacity(106, out _));
        Assert.True(encoder.TryInsert(new QPackFieldLine(":authority", "www.example.com"), out _));
        Assert.True(encoder.TryInsert(new QPackFieldLine(":path", "/sample/path"), out _));

        encoder.DecodeDecoderStream(Convert.FromHexString("02"));

        Assert.True(encoder.TryInsert(new QPackFieldLine("custom-key", "custom-value"), out _));
        Assert.Equal(3UL, encoder.DynamicTable.InsertCount);
        Assert.Equal(1UL, encoder.DynamicTable.DroppedCount);
        Assert.Equal(103, encoder.DynamicTable.CurrentSize);
    }

    [Fact]
    public void Encoder_UsesDynamicReferencesWhenBlockedStreamLimitPermits()
    {
        QPackEncoder encoder = new(maximumDynamicTableCapacity: 220, maximumBlockedStreams: 1);
        Assert.True(encoder.TrySetDynamicTableCapacity(220, out _));
        Assert.True(encoder.TryInsert(new QPackFieldLine(":authority", "www.example.com"), out _));
        Assert.True(encoder.TryInsert(new QPackFieldLine(":path", "/sample/path"), out _));

        QPackFieldSectionEncodeResult encoded = encoder.EncodeFieldSection(
            4,
            [
                new QPackFieldLine(":authority", "www.example.com"),
                new QPackFieldLine(":path", "/sample/path"),
            ]);

        Assert.Equal(2UL, encoded.RequiredInsertCount);
        Assert.Equal("03008180", Convert.ToHexString(encoded.EncodedFieldSection));
    }

    [Fact]
    public void Encoder_AvoidsDynamicReferencesWhenBlockedStreamLimitIsZero()
    {
        QPackEncoder encoder = new(maximumDynamicTableCapacity: 220, maximumBlockedStreams: 0);
        Assert.True(encoder.TrySetDynamicTableCapacity(220, out _));
        Assert.True(encoder.TryInsert(new QPackFieldLine(":authority", "www.example.com"), out _));

        QPackFieldSectionEncodeResult encoded = encoder.EncodeFieldSection(
            4,
            [
                new QPackFieldLine(":authority", "www.example.com"),
            ]);

        Assert.Equal(0UL, encoded.RequiredInsertCount);
        Assert.Equal("0000500F7777772E6578616D706C652E636F6D", Convert.ToHexString(encoded.EncodedFieldSection));
    }
}
