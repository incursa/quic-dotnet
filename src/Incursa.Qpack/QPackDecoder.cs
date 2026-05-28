using System.Buffers;
using System.Text;

namespace Incursa.Qpack;

/// <summary>
/// Decodes QPACK field sections and encoder-stream instructions.
/// </summary>
public sealed class QPackDecoder
{
    private const byte IndexedFieldMask = 0x80;
    private const byte StaticReferenceMask = 0x40;
    private const byte TwoBitPatternMask = 0xC0;
    private const byte LiteralWithNameReferencePattern = 0x40;
    private const byte FourBitPatternMask = 0xF0;
    private const byte PostBaseIndexedPattern = 0x10;
    private const byte PostBaseNameReferencePattern = 0x00;
    private const byte ThreeBitPatternMask = 0xE0;
    private const byte LiteralWithLiteralNamePattern = 0x20;
    private const byte BaseSignMask = 0x80;
    private const byte NameReferenceStaticTableMask = 0x10;
    private const byte EncoderInstructionIndexedNameMask = 0x80;
    private const byte EncoderInstructionStaticNameMask = 0x40;
    private const byte EncoderInstructionSetCapacityPattern = 0x20;
    private const byte EncoderInstructionLiteralNamePattern = 0x40;
    private const byte EncoderInstructionThreeBitMask = 0xE0;
    private const byte EncoderInstructionTwoBitMask = 0xC0;
    private const int RequiredInsertCountPrefixBits = 8;
    private const int BasePrefixBits = 7;
    private const int IndexedFieldPrefixBits = 6;
    private const int NameReferencePrefixBits = 4;
    private const int PostBaseIndexedPrefixBits = 4;
    private const int PostBaseNameReferencePrefixBits = 3;
    private const int LiteralNamePrefixBits = 4;
    private const int ValueStringPrefixBits = 8;
    private const int SetCapacityPrefixBits = 5;
    private const int EncoderNameReferencePrefixBits = 6;
    private const int EncoderLiteralNamePrefixBits = 6;
    private const int DuplicatePrefixBits = 5;
    private const int MinimumDynamicTableEntrySize = 32;
    private const ulong RequiredInsertCountModuloMultiplier = 2;
    private const int MaxPrefixBitCount = 8;

    private readonly QPackDynamicTable dynamicTable;
    private readonly Dictionary<ulong, BlockedFieldSection> blockedFieldSections = [];
    private readonly int maximumBlockedStreams;
    private byte[] pendingEncoderStreamInstructions = [];

    /// <summary>
    /// Initializes a new instance of the <see cref="QPackDecoder" /> class.
    /// </summary>
    public QPackDecoder(int maximumDynamicTableCapacity, int maximumBlockedStreams)
    {
        if (maximumDynamicTableCapacity < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumDynamicTableCapacity));
        }

        if (maximumBlockedStreams < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumBlockedStreams));
        }

        dynamicTable = new QPackDynamicTable(maximumDynamicTableCapacity);
        this.maximumBlockedStreams = maximumBlockedStreams;
    }

    /// <summary>
    /// Gets the decoder dynamic table.
    /// </summary>
    public QPackDynamicTable DynamicTable => dynamicTable;

    /// <summary>
    /// Gets the number of streams currently blocked by Required Insert Count.
    /// </summary>
    public int BlockedStreamCount => blockedFieldSections.Count;

    /// <summary>
    /// Decodes an ordered field section without dynamic table state.
    /// </summary>
    public static QPackFieldLine[] DecodeFieldSection(ReadOnlySpan<byte> encodedFieldSection)
    {
        QPackDecoder decoder = new(0, 0);
        QPackFieldSectionDecodeResult result = decoder.DecodeFieldSection(0, encodedFieldSection.ToArray());
        if (result.IsBlocked)
        {
            throw new QPackException(QPackErrorCode.DecompressionFailed, "The QPACK field section is blocked.");
        }

        return result.FieldLines;
    }

    /// <summary>
    /// Decodes an ordered field section without dynamic table state.
    /// </summary>
    public static QPackFieldLine[] DecodeFieldSection(ReadOnlyMemory<byte> encodedFieldSection)
    {
        return DecodeFieldSection(encodedFieldSection.Span);
    }

    /// <summary>
    /// Decodes an ordered field section or records it as blocked.
    /// </summary>
    public QPackFieldSectionDecodeResult DecodeFieldSection(ulong streamId, ReadOnlyMemory<byte> encodedFieldSection)
    {
        FieldSectionPrefix prefix = DecodeFieldSectionPrefix(encodedFieldSection.Span);
        if (prefix.RequiredInsertCount > dynamicTable.InsertCount)
        {
            if (!blockedFieldSections.ContainsKey(streamId) && blockedFieldSections.Count >= maximumBlockedStreams)
            {
                throw new QPackException(QPackErrorCode.DecompressionFailed, "The QPACK blocked stream limit was exceeded.");
            }

            blockedFieldSections[streamId] = new BlockedFieldSection(streamId, encodedFieldSection.ToArray(), prefix.RequiredInsertCount);
            return new QPackFieldSectionDecodeResult(streamId, true, prefix.RequiredInsertCount, []);
        }

        QPackFieldLine[] fields = DecodeAvailableFieldSection(encodedFieldSection.Span, prefix);
        return new QPackFieldSectionDecodeResult(streamId, false, prefix.RequiredInsertCount, fields);
    }

    internal QPackFieldSectionDecodeStatus DecodeFieldSection(
        ulong streamId,
        ReadOnlyMemory<byte> encodedFieldSection,
        IBufferWriter<QPackFieldLine> fieldSink)
    {
        ArgumentNullException.ThrowIfNull(fieldSink);

        FieldSectionPrefix prefix = DecodeFieldSectionPrefix(encodedFieldSection.Span);
        if (prefix.RequiredInsertCount > dynamicTable.InsertCount)
        {
            if (!blockedFieldSections.ContainsKey(streamId) && blockedFieldSections.Count >= maximumBlockedStreams)
            {
                throw new QPackException(QPackErrorCode.DecompressionFailed, "The QPACK blocked stream limit was exceeded.");
            }

            blockedFieldSections[streamId] = new BlockedFieldSection(streamId, encodedFieldSection.ToArray(), prefix.RequiredInsertCount);
            return new QPackFieldSectionDecodeStatus(streamId, true, prefix.RequiredInsertCount);
        }

        DecodeAvailableFieldSection(encodedFieldSection.Span, prefix, fieldSink);
        return new QPackFieldSectionDecodeStatus(streamId, false, prefix.RequiredInsertCount);
    }

    /// <summary>
    /// Applies encoder-stream instructions and returns field sections that became unblocked.
    /// </summary>
    public QPackFieldSectionDecodeResult[] DecodeEncoderStream(
        ReadOnlySpan<byte> encoderStreamInstructions,
        bool endOfStream = false)
    {
        pendingEncoderStreamInstructions = Append(pendingEncoderStreamInstructions, encoderStreamInstructions);
        int index = 0;
        while (index < pendingEncoderStreamInstructions.Length)
        {
            if (!TryDecodeEncoderStreamInstruction(pendingEncoderStreamInstructions, ref index))
            {
                break;
            }
        }

        pendingEncoderStreamInstructions = SlicePending(pendingEncoderStreamInstructions, index);
        if (endOfStream && pendingEncoderStreamInstructions.Length != 0)
        {
            throw new QPackException(QPackErrorCode.EncoderStreamError, "The QPACK encoder stream ended with a partial instruction.");
        }

        return DecodeUnblockedFieldSections();
    }

    /// <summary>
    /// Signals that the encoder stream ended and validates that no partial instruction remains.
    /// </summary>
    public QPackFieldSectionDecodeResult[] CompleteEncoderStream()
    {
        return DecodeEncoderStream([], endOfStream: true);
    }

    private FieldSectionPrefix DecodeFieldSectionPrefix(ReadOnlySpan<byte> source)
    {
        int index = 0;
        ulong encodedInsertCount = ReadInteger(source, ref index, RequiredInsertCountPrefixBits, QPackErrorCode.DecompressionFailed);
        ulong requiredInsertCount = DecodeRequiredInsertCount(encodedInsertCount);
        int baseFirstByteIndex = index;
        ulong deltaBase = ReadInteger(source, ref index, BasePrefixBits, QPackErrorCode.DecompressionFailed);
        bool sign = (source[baseFirstByteIndex] & BaseSignMask) != 0;

        if (sign && requiredInsertCount <= deltaBase)
        {
            throw new QPackException(QPackErrorCode.DecompressionFailed, "The QPACK field section Base is invalid.");
        }

        ulong baseIndex = sign ? requiredInsertCount - deltaBase - 1 : requiredInsertCount + deltaBase;
        return new FieldSectionPrefix(requiredInsertCount, baseIndex, index);
    }

    private QPackFieldLine[] DecodeAvailableFieldSection(ReadOnlySpan<byte> encodedFieldSection, FieldSectionPrefix prefix)
    {
        int index = prefix.BytesConsumed;
        int remainingRepresentationBytes = encodedFieldSection.Length - index;
        ArrayBufferWriter<QPackFieldLine> fields = remainingRepresentationBytes == 0
            ? new()
            : new(GetInitialFieldLineCapacity(remainingRepresentationBytes));
        DecodeAvailableFieldSection(encodedFieldSection, prefix, fields);
        return fields.WrittenSpan.ToArray();
    }

    private void DecodeAvailableFieldSection(
        ReadOnlySpan<byte> encodedFieldSection,
        FieldSectionPrefix prefix,
        IBufferWriter<QPackFieldLine> fields)
    {
        int index = prefix.BytesConsumed;
        ulong largestReferencedInsertCount = 0;

        while (index < encodedFieldSection.Length)
        {
            byte first = encodedFieldSection[index];
            if ((first & IndexedFieldMask) != 0)
            {
                DecodeIndexedField(encodedFieldSection, ref index, prefix, fields, ref largestReferencedInsertCount);
            }
            else if ((first & TwoBitPatternMask) == LiteralWithNameReferencePattern)
            {
                DecodeLiteralWithNameReference(encodedFieldSection, ref index, prefix, fields, ref largestReferencedInsertCount);
            }
            else if ((first & FourBitPatternMask) == PostBaseIndexedPattern)
            {
                DecodePostBaseIndexedField(encodedFieldSection, ref index, prefix, fields, ref largestReferencedInsertCount);
            }
            else if ((first & FourBitPatternMask) == PostBaseNameReferencePattern)
            {
                DecodeLiteralWithPostBaseNameReference(encodedFieldSection, ref index, prefix, fields, ref largestReferencedInsertCount);
            }
            else if ((first & ThreeBitPatternMask) == LiteralWithLiteralNamePattern)
            {
                DecodeLiteralWithLiteralName(encodedFieldSection, ref index, fields);
            }
            else
            {
                throw new QPackException(QPackErrorCode.DecompressionFailed, "The QPACK field line representation is invalid.");
            }
        }

        if (largestReferencedInsertCount > prefix.RequiredInsertCount)
        {
            throw new QPackException(QPackErrorCode.DecompressionFailed, "The QPACK Required Insert Count is too small.");
        }
    }

    private static int GetInitialFieldLineCapacity(int encodedRepresentationBytes)
    {
        const int MaximumInitialFieldLineCapacity = 32;

        return Math.Min(encodedRepresentationBytes, MaximumInitialFieldLineCapacity);
    }

    private void DecodeIndexedField(
        ReadOnlySpan<byte> source,
        ref int index,
        FieldSectionPrefix prefix,
        IBufferWriter<QPackFieldLine> fields,
        ref ulong largestReferencedInsertCount)
    {
        bool staticReference = (source[index] & StaticReferenceMask) != 0;
        ulong tableIndex = ReadInteger(source, ref index, IndexedFieldPrefixBits, QPackErrorCode.DecompressionFailed);
        if (staticReference)
        {
            WriteField(fields, QPackStaticTable.GetRequired(tableIndex));
            return;
        }

        QPackDynamicTableEntry entry = GetDynamicByRelativeIndex(prefix.Base, tableIndex, prefix.RequiredInsertCount);
        largestReferencedInsertCount = Math.Max(largestReferencedInsertCount, entry.AbsoluteIndex + 1);
        WriteField(fields, entry.FieldLine);
    }

    private void DecodePostBaseIndexedField(
        ReadOnlySpan<byte> source,
        ref int index,
        FieldSectionPrefix prefix,
        IBufferWriter<QPackFieldLine> fields,
        ref ulong largestReferencedInsertCount)
    {
        ulong tableIndex = ReadInteger(source, ref index, PostBaseIndexedPrefixBits, QPackErrorCode.DecompressionFailed);
        QPackDynamicTableEntry entry = GetDynamicByPostBaseIndex(prefix.Base, tableIndex, prefix.RequiredInsertCount);
        largestReferencedInsertCount = Math.Max(largestReferencedInsertCount, entry.AbsoluteIndex + 1);
        WriteField(fields, entry.FieldLine);
    }

    private void DecodeLiteralWithNameReference(
        ReadOnlySpan<byte> source,
        ref int index,
        FieldSectionPrefix prefix,
        IBufferWriter<QPackFieldLine> fields,
        ref ulong largestReferencedInsertCount)
    {
        bool staticReference = (source[index] & NameReferenceStaticTableMask) != 0;
        ulong tableIndex = ReadInteger(source, ref index, NameReferencePrefixBits, QPackErrorCode.DecompressionFailed);
        string name;
        if (staticReference)
        {
            name = QPackStaticTable.GetRequired(tableIndex).Name;
        }
        else
        {
            QPackDynamicTableEntry entry = GetDynamicByRelativeIndex(prefix.Base, tableIndex, prefix.RequiredInsertCount);
            largestReferencedInsertCount = Math.Max(largestReferencedInsertCount, entry.AbsoluteIndex + 1);
            name = entry.FieldLine.Name;
        }

        string value = ReadString(source, ref index, ValueStringPrefixBits, QPackErrorCode.DecompressionFailed);
        WriteField(fields, new QPackFieldLine(name, value));
    }

    private void DecodeLiteralWithPostBaseNameReference(
        ReadOnlySpan<byte> source,
        ref int index,
        FieldSectionPrefix prefix,
        IBufferWriter<QPackFieldLine> fields,
        ref ulong largestReferencedInsertCount)
    {
        ulong tableIndex = ReadInteger(source, ref index, PostBaseNameReferencePrefixBits, QPackErrorCode.DecompressionFailed);
        QPackDynamicTableEntry entry = GetDynamicByPostBaseIndex(prefix.Base, tableIndex, prefix.RequiredInsertCount);
        largestReferencedInsertCount = Math.Max(largestReferencedInsertCount, entry.AbsoluteIndex + 1);
        string value = ReadString(source, ref index, ValueStringPrefixBits, QPackErrorCode.DecompressionFailed);
        WriteField(fields, new QPackFieldLine(entry.FieldLine.Name, value));
    }

    private static void DecodeLiteralWithLiteralName(
        ReadOnlySpan<byte> source,
        ref int index,
        IBufferWriter<QPackFieldLine> fields)
    {
        string name = ReadString(source, ref index, LiteralNamePrefixBits, QPackErrorCode.DecompressionFailed);
        string value = ReadString(source, ref index, ValueStringPrefixBits, QPackErrorCode.DecompressionFailed);
        WriteField(fields, new QPackFieldLine(name, value));
    }

    private void InsertFromEncoderStream(QPackFieldLine fieldLine)
    {
        if (!dynamicTable.TryInsert(fieldLine, out _))
        {
            throw new QPackException(QPackErrorCode.EncoderStreamError, "The QPACK dynamic table entry is larger than the current capacity.");
        }
    }

    private QPackFieldSectionDecodeResult[] DecodeUnblockedFieldSections()
    {
        if (blockedFieldSections.Count == 0)
        {
            return [];
        }

        List<QPackFieldSectionDecodeResult> unblocked = [];
        foreach (BlockedFieldSection blocked in blockedFieldSections.Values.ToArray())
        {
            if (blocked.RequiredInsertCount > dynamicTable.InsertCount)
            {
                continue;
            }

            FieldSectionPrefix prefix = DecodeFieldSectionPrefix(blocked.EncodedFieldSection);
            QPackFieldLine[] fields = DecodeAvailableFieldSection(blocked.EncodedFieldSection, prefix);
            unblocked.Add(new QPackFieldSectionDecodeResult(blocked.StreamId, false, prefix.RequiredInsertCount, fields));
            blockedFieldSections.Remove(blocked.StreamId);
        }

        return [.. unblocked];
    }

    private ulong DecodeRequiredInsertCount(ulong encodedInsertCount)
    {
        if (encodedInsertCount == 0)
        {
            return 0;
        }

        ulong maxEntries = checked((ulong)dynamicTable.MaximumCapacity) / MinimumDynamicTableEntrySize;
        ulong fullRange = RequiredInsertCountModuloMultiplier * maxEntries;
        if (fullRange == 0 || encodedInsertCount > fullRange)
        {
            throw new QPackException(QPackErrorCode.DecompressionFailed, "The QPACK Required Insert Count is invalid.");
        }

        ulong maxValue = dynamicTable.InsertCount + maxEntries;
        ulong maxWrapped = maxValue / fullRange * fullRange;
        ulong requiredInsertCount = maxWrapped + encodedInsertCount - 1;
        if (requiredInsertCount > maxValue)
        {
            if (requiredInsertCount <= fullRange)
            {
                throw new QPackException(QPackErrorCode.DecompressionFailed, "The QPACK Required Insert Count is invalid.");
            }

            requiredInsertCount -= fullRange;
        }

        if (requiredInsertCount == 0)
        {
            throw new QPackException(QPackErrorCode.DecompressionFailed, "The QPACK Required Insert Count is invalid.");
        }

        return requiredInsertCount;
    }

    private QPackDynamicTableEntry GetDynamicByRelativeIndex(
        ulong baseIndex,
        ulong relativeIndex,
        ulong requiredInsertCount)
    {
        if (!dynamicTable.TryGetByRelativeIndex(baseIndex, relativeIndex, out QPackDynamicTableEntry entry)
            || entry.AbsoluteIndex >= requiredInsertCount)
        {
            throw new QPackException(QPackErrorCode.DecompressionFailed, "The QPACK dynamic table reference is invalid.");
        }

        return entry;
    }

    private QPackDynamicTableEntry GetDynamicByPostBaseIndex(
        ulong baseIndex,
        ulong postBaseIndex,
        ulong requiredInsertCount)
    {
        if (!dynamicTable.TryGetByPostBaseIndex(baseIndex, postBaseIndex, out QPackDynamicTableEntry entry)
            || entry.AbsoluteIndex >= requiredInsertCount)
        {
            throw new QPackException(QPackErrorCode.DecompressionFailed, "The QPACK dynamic table post-Base reference is invalid.");
        }

        return entry;
    }

    private static ulong ReadInteger(ReadOnlySpan<byte> source, ref int index, int prefixBitCount, QPackErrorCode errorCode)
    {
        if (index >= source.Length)
        {
            throw new QPackException(errorCode, "The QPACK integer is truncated.");
        }

        try
        {
            ulong value = QPackInteger.Decode(source[index..], prefixBitCount, out int bytesConsumed);
            index += bytesConsumed;
            return value;
        }
        catch (QPackException exception) when (exception.ErrorCode == QPackErrorCode.DecompressionFailed && errorCode != QPackErrorCode.DecompressionFailed)
        {
            throw new QPackException(errorCode, exception.Message);
        }
    }

    private bool TryDecodeEncoderStreamInstruction(ReadOnlySpan<byte> source, ref int index)
    {
        byte first = source[index];
        if ((first & EncoderInstructionIndexedNameMask) != 0)
        {
            return TryDecodeInsertWithNameReference(source, ref index);
        }

        if ((first & EncoderInstructionThreeBitMask) == EncoderInstructionSetCapacityPattern)
        {
            return TryDecodeSetDynamicTableCapacity(source, ref index);
        }

        if ((first & EncoderInstructionTwoBitMask) == EncoderInstructionLiteralNamePattern)
        {
            return TryDecodeInsertWithLiteralName(source, ref index);
        }

        return TryDecodeDuplicate(source, ref index);
    }

    private bool TryDecodeSetDynamicTableCapacity(ReadOnlySpan<byte> source, ref int index)
    {
        int localIndex = index;
        if (!TryReadInteger(source, ref localIndex, SetCapacityPrefixBits, QPackErrorCode.EncoderStreamError, out ulong capacity))
        {
            return false;
        }

        if (capacity > int.MaxValue || !dynamicTable.TrySetCapacity((int)capacity))
        {
            throw new QPackException(QPackErrorCode.EncoderStreamError, "The QPACK dynamic table capacity is invalid.");
        }

        index = localIndex;
        return true;
    }

    private bool TryDecodeInsertWithNameReference(ReadOnlySpan<byte> source, ref int index)
    {
        int localIndex = index;
        bool staticReference = (source[localIndex] & EncoderInstructionStaticNameMask) != 0;
        if (!TryReadInteger(source, ref localIndex, EncoderNameReferencePrefixBits, QPackErrorCode.EncoderStreamError, out ulong tableIndex)
            || !TryReadString(source, ref localIndex, ValueStringPrefixBits, QPackErrorCode.EncoderStreamError, out string value))
        {
            return false;
        }

        string name;
        if (staticReference)
        {
            try
            {
                name = QPackStaticTable.GetRequired(tableIndex).Name;
            }
            catch (QPackException exception) when (exception.ErrorCode == QPackErrorCode.DecompressionFailed)
            {
                throw new QPackException(QPackErrorCode.EncoderStreamError, "The QPACK encoder-stream static table index is invalid.");
            }
        }
        else
        {
            if (!dynamicTable.TryGetByEncoderRelativeIndex(tableIndex, out QPackDynamicTableEntry entry))
            {
                throw new QPackException(QPackErrorCode.EncoderStreamError, "The QPACK encoder-stream dynamic table index is invalid.");
            }

            name = entry.FieldLine.Name;
        }

        InsertFromEncoderStream(new QPackFieldLine(name, value));
        index = localIndex;
        return true;
    }

    private bool TryDecodeInsertWithLiteralName(ReadOnlySpan<byte> source, ref int index)
    {
        int localIndex = index;
        if (!TryReadString(source, ref localIndex, EncoderLiteralNamePrefixBits, QPackErrorCode.EncoderStreamError, out string name)
            || !TryReadString(source, ref localIndex, ValueStringPrefixBits, QPackErrorCode.EncoderStreamError, out string value))
        {
            return false;
        }

        InsertFromEncoderStream(new QPackFieldLine(name, value));
        index = localIndex;
        return true;
    }

    private bool TryDecodeDuplicate(ReadOnlySpan<byte> source, ref int index)
    {
        int localIndex = index;
        if (!TryReadInteger(source, ref localIndex, DuplicatePrefixBits, QPackErrorCode.EncoderStreamError, out ulong relativeIndex))
        {
            return false;
        }

        if (!dynamicTable.TryDuplicate(relativeIndex, out _))
        {
            throw new QPackException(QPackErrorCode.EncoderStreamError, "The QPACK Duplicate instruction index is invalid.");
        }

        index = localIndex;
        return true;
    }

    private static bool TryReadInteger(
        ReadOnlySpan<byte> source,
        ref int index,
        int prefixBitCount,
        QPackErrorCode errorCode,
        out ulong value)
    {
        value = default;
        if (index >= source.Length)
        {
            return false;
        }

        if (TryReadIntegerPartial(source[index..], prefixBitCount, errorCode, out value, out int bytesConsumed))
        {
            index += bytesConsumed;
            return true;
        }

        return false;
    }

    private static bool TryReadIntegerPartial(
        ReadOnlySpan<byte> source,
        int prefixBitCount,
        QPackErrorCode errorCode,
        out ulong value,
        out int bytesConsumed)
    {
        const byte continuationValueMask = 0x7F;
        const byte continuationFlag = 0x80;
        const int continuationShift = 7;
        const int maximumContinuationShift = 63;

        value = default;
        bytesConsumed = default;
        ulong mask = GetPrefixMask(prefixBitCount);
        value = source[0] & mask;
        bytesConsumed = 1;
        if (value < mask)
        {
            return true;
        }

        int shift = 0;
        while (bytesConsumed < source.Length)
        {
            byte next = source[bytesConsumed++];
            ulong segment = (ulong)(next & continuationValueMask);
            if (shift >= maximumContinuationShift || (segment << shift) > QPackInteger.MaxValue - value)
            {
                throw new QPackException(errorCode, "The QPACK prefixed integer is malformed.");
            }

            value += segment << shift;
            if ((next & continuationFlag) == 0)
            {
                if (value > QPackInteger.MaxValue)
                {
                    throw new QPackException(errorCode, "The QPACK prefixed integer is malformed.");
                }

                return true;
            }

            shift += continuationShift;
        }

        return false;
    }

    private static bool TryReadString(
        ReadOnlySpan<byte> source,
        ref int index,
        int prefixBitCount,
        QPackErrorCode errorCode,
        out string value)
    {
        value = string.Empty;
        if (index >= source.Length)
        {
            return false;
        }

        bool huffmanEncoded = (source[index] & (1 << (prefixBitCount - 1))) != 0;
        int localIndex = index;
        if (!TryReadInteger(source, ref localIndex, prefixBitCount - 1, errorCode, out ulong length))
        {
            return false;
        }

        if (length > int.MaxValue)
        {
            throw new QPackException(errorCode, "The QPACK string literal length is invalid.");
        }

        if ((ulong)(source.Length - localIndex) < length)
        {
            return false;
        }

        ReadOnlySpan<byte> encodedString = source.Slice(localIndex, (int)length);
        value = huffmanEncoded
            ? QPackHuffman.Decode(encodedString, errorCode)
            : Encoding.Latin1.GetString(encodedString);
        index = checked(localIndex + (int)length);
        return true;
    }

    private static byte GetPrefixMask(int prefixBitCount)
    {
        return prefixBitCount == MaxPrefixBitCount ? byte.MaxValue : (byte)((1 << prefixBitCount) - 1);
    }

    private static byte[] Append(byte[] pending, ReadOnlySpan<byte> source)
    {
        if (source.IsEmpty)
        {
            return pending;
        }

        byte[] combined = new byte[pending.Length + source.Length];
        pending.CopyTo(combined, 0);
        source.CopyTo(combined.AsSpan(pending.Length));
        return combined;
    }

    private static byte[] SlicePending(byte[] pending, int consumed)
    {
        return consumed == 0 ? pending : pending.AsSpan(consumed).ToArray();
    }

    private static string ReadString(ReadOnlySpan<byte> source, ref int index, int prefixBitCount, QPackErrorCode errorCode)
    {
        if (index >= source.Length)
        {
            throw new QPackException(errorCode, "The QPACK string literal is truncated.");
        }

        try
        {
            string value = QPackStringLiteral.Read(source[index..], prefixBitCount, out int bytesConsumed);
            index += bytesConsumed;
            return value;
        }
        catch (QPackException exception) when (exception.ErrorCode == QPackErrorCode.DecompressionFailed && errorCode != QPackErrorCode.DecompressionFailed)
        {
            throw new QPackException(errorCode, exception.Message);
        }
    }

    private static void WriteField(IBufferWriter<QPackFieldLine> fields, QPackFieldLine fieldLine)
    {
        Span<QPackFieldLine> destination = fields.GetSpan(1);
        destination[0] = fieldLine;
        fields.Advance(1);
    }

    private readonly record struct FieldSectionPrefix(ulong RequiredInsertCount, ulong Base, int BytesConsumed);

    private sealed record BlockedFieldSection(ulong StreamId, byte[] EncodedFieldSection, ulong RequiredInsertCount);
}
