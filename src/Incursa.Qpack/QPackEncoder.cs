using System.Buffers;

namespace Incursa.Qpack;

/// <summary>
/// Encodes QPACK field sections and encoder-stream instructions.
/// </summary>
public sealed class QPackEncoder
{
    private const int FieldSectionRequiredInsertCountPrefixBits = 8;
    private const int FieldSectionBasePrefixBits = 7;
    private const int StaticIndexedFieldPrefixBits = 6;
    private const byte StaticIndexedFieldPrefix = 0xC0;
    private const byte DynamicIndexedFieldPrefix = 0x80;
    private const int StaticNameReferencePrefixBits = 4;
    private const byte LiteralWithStaticNameReferencePrefix = 0x50;
    private const byte LiteralWithDynamicNameReferencePrefix = 0x40;
    private const int DynamicNameReferencePrefixBits = 4;
    private const int LiteralNamePrefixBits = 4;
    private const byte LiteralWithLiteralNamePrefix = 0x20;
    private const int ValueStringPrefixBits = 8;
    private const int SetCapacityPrefixBits = 5;
    private const byte SetCapacityPrefix = 0x20;
    private const int InsertNameReferencePrefixBits = 6;
    private const byte InsertStaticNameReferencePrefix = 0xC0;
    private const byte InsertDynamicNameReferencePrefix = 0x80;
    private const int InsertLiteralNamePrefixBits = 6;
    private const byte InsertLiteralNamePrefix = 0x40;
    private const int DuplicatePrefixBits = 5;
    private const int DecoderStreamInsertCountIncrementPrefixBits = 6;
    private const int DecoderStreamCancellationPrefixBits = 6;
    private const int DecoderStreamSectionAcknowledgmentPrefixBits = 7;
    private const byte DecoderStreamSectionAcknowledgmentMask = 0x80;
    private const byte DecoderStreamCancellationPattern = 0x40;
    private const byte DecoderStreamTwoBitMask = 0xC0;
    private const byte FieldSectionBaseSignPrefix = 0x80;
    private const int MinimumDynamicTableEntrySize = 32;
    private const ulong RequiredInsertCountModuloMultiplier = 2;
    private const byte ContinuationValueMask = 0x7F;
    private const byte ContinuationFlag = 0x80;
    private const int ContinuationShift = 7;
    private const int MaximumContinuationShift = 63;
    private const int MaxPrefixBitCount = 8;

    private readonly QPackDynamicTable dynamicTable;
    private readonly Dictionary<ulong, int> outstandingReferenceCounts = [];
    private readonly Dictionary<ulong, Queue<OutstandingFieldSection>> outstandingFieldSectionsByStream = [];
    private readonly int maximumBlockedStreams;
    private int blockedStreamRiskCount;
    private byte[] pendingDecoderStreamInstructions = [];

    /// <summary>
    /// Initializes a new instance of the <see cref="QPackEncoder" /> class.
    /// </summary>
    public QPackEncoder(int maximumDynamicTableCapacity, int maximumBlockedStreams)
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
    /// Gets the encoder dynamic table.
    /// </summary>
    public QPackDynamicTable DynamicTable => dynamicTable;

    /// <summary>
    /// Gets the largest insert count known to have been received by the decoder.
    /// </summary>
    public ulong KnownReceivedCount { get; private set; }

    /// <summary>
    /// Encodes an ordered field section using only literals and static table references.
    /// </summary>
    public static byte[] EncodeFieldSection(IEnumerable<QPackFieldLine> fieldLines)
    {
        ArgumentNullException.ThrowIfNull(fieldLines);

        ArrayBufferWriter<byte> writer = new();

        QPackInteger.Write(writer, 0, FieldSectionRequiredInsertCountPrefixBits);
        QPackInteger.Write(writer, 0, FieldSectionBasePrefixBits);

        foreach (QPackFieldLine fieldLine in fieldLines)
        {
            ValidateFieldLine(fieldLine);
            int staticFieldIndex = QPackStaticTable.FindFieldLineIndex(fieldLine);
            if (staticFieldIndex >= 0)
            {
                WriteStaticIndexedField(writer, staticFieldIndex);
                continue;
            }

            int staticNameIndex = QPackStaticTable.FindNameIndex(fieldLine.Name);
            if (staticNameIndex >= 0)
            {
                WriteLiteralWithStaticNameReference(writer, staticNameIndex, fieldLine.Value);
                continue;
            }

            WriteLiteralWithLiteralName(writer, fieldLine);
        }

        return writer.WrittenSpan.ToArray();
    }

    /// <summary>
    /// Encodes an ordered field section, using dynamic references when they are admissible.
    /// </summary>
    public QPackFieldSectionEncodeResult EncodeFieldSection(ulong streamId, IEnumerable<QPackFieldLine> fieldLines)
    {
        ArgumentNullException.ThrowIfNull(fieldLines);

        ArrayBufferWriter<byte> representations = new();
        ulong baseIndex = dynamicTable.InsertCount;
        ulong requiredInsertCount = 0;
        HashSet<ulong> referencedEntries = [];

        foreach (QPackFieldLine fieldLine in fieldLines)
        {
            ValidateFieldLine(fieldLine);
            int staticFieldIndex = QPackStaticTable.FindFieldLineIndex(fieldLine);
            if (staticFieldIndex >= 0)
            {
                WriteStaticIndexedField(representations, staticFieldIndex);
                continue;
            }

            int dynamicFieldIndex = dynamicTable.FindFieldLineAbsoluteIndex(fieldLine);
            if (dynamicFieldIndex >= 0 && CanReferenceDynamicEntry((ulong)dynamicFieldIndex, referencedEntries))
            {
                ulong absoluteIndex = (ulong)dynamicFieldIndex;
                WriteDynamicIndexedField(representations, baseIndex, absoluteIndex);
                requiredInsertCount = Math.Max(requiredInsertCount, absoluteIndex + 1);
                referencedEntries.Add(absoluteIndex);
                continue;
            }

            int staticNameIndex = QPackStaticTable.FindNameIndex(fieldLine.Name);
            if (staticNameIndex >= 0)
            {
                WriteLiteralWithStaticNameReference(representations, staticNameIndex, fieldLine.Value);
                continue;
            }

            int dynamicNameIndex = dynamicTable.FindNameAbsoluteIndex(fieldLine.Name);
            if (dynamicNameIndex >= 0 && CanReferenceDynamicEntry((ulong)dynamicNameIndex, referencedEntries))
            {
                ulong absoluteIndex = (ulong)dynamicNameIndex;
                WriteLiteralWithDynamicNameReference(representations, baseIndex, absoluteIndex, fieldLine.Value);
                requiredInsertCount = Math.Max(requiredInsertCount, absoluteIndex + 1);
                referencedEntries.Add(absoluteIndex);
                continue;
            }

            WriteLiteralWithLiteralName(representations, fieldLine);
        }

        ArrayBufferWriter<byte> writer = new();
        WriteFieldSectionPrefix(writer, requiredInsertCount, baseIndex);
        writer.Write(representations.WrittenSpan);

        if (requiredInsertCount != 0)
        {
            TrackOutstandingReferences(streamId, requiredInsertCount, referencedEntries);
        }

        return new QPackFieldSectionEncodeResult(writer.WrittenSpan.ToArray(), [], requiredInsertCount);
    }

    /// <summary>
    /// Emits and applies a Set Dynamic Table Capacity encoder instruction.
    /// </summary>
    public bool TrySetDynamicTableCapacity(int capacity, out byte[] encoderStreamInstruction)
    {
        encoderStreamInstruction = [];
        if (!dynamicTable.TrySetCapacity(capacity, IsEvictable))
        {
            return false;
        }

        ArrayBufferWriter<byte> writer = new();
        QPackInteger.Write(writer, checked((ulong)capacity), SetCapacityPrefixBits, SetCapacityPrefix);
        encoderStreamInstruction = writer.WrittenSpan.ToArray();
        return true;
    }

    /// <summary>
    /// Emits and applies an encoder-stream insert instruction.
    /// </summary>
    public bool TryInsert(QPackFieldLine fieldLine, out byte[] encoderStreamInstruction)
    {
        ValidateFieldLine(fieldLine);
        encoderStreamInstruction = [];

        int entrySize = QPackDynamicTable.GetEntrySize(fieldLine);
        if (entrySize > dynamicTable.Capacity)
        {
            return false;
        }

        ArrayBufferWriter<byte> writer = new();
        int staticNameIndex = QPackStaticTable.FindNameIndex(fieldLine.Name);
        if (staticNameIndex >= 0)
        {
            QPackInteger.Write(writer, checked((ulong)staticNameIndex), InsertNameReferencePrefixBits, InsertStaticNameReferencePrefix);
            QPackStringLiteral.Write(writer, fieldLine.Value, ValueStringPrefixBits);
        }
        else
        {
            int dynamicNameIndex = dynamicTable.FindNameAbsoluteIndex(fieldLine.Name);
            if (dynamicNameIndex >= 0)
            {
                ulong relativeIndex = dynamicTable.InsertCount - (ulong)dynamicNameIndex - 1;
                QPackInteger.Write(writer, relativeIndex, InsertNameReferencePrefixBits, InsertDynamicNameReferencePrefix);
                QPackStringLiteral.Write(writer, fieldLine.Value, ValueStringPrefixBits);
            }
            else
            {
                QPackStringLiteral.Write(writer, fieldLine.Name, InsertLiteralNamePrefixBits, InsertLiteralNamePrefix);
                QPackStringLiteral.Write(writer, fieldLine.Value, ValueStringPrefixBits);
            }
        }

        if (!dynamicTable.TryInsert(fieldLine, out _, IsEvictable))
        {
            return false;
        }

        encoderStreamInstruction = writer.WrittenSpan.ToArray();
        return true;
    }

    /// <summary>
    /// Emits and applies an encoder-stream Duplicate instruction.
    /// </summary>
    public bool TryDuplicate(ulong relativeIndex, out byte[] encoderStreamInstruction)
    {
        encoderStreamInstruction = [];
        if (!dynamicTable.TryDuplicate(relativeIndex, out _, IsEvictable))
        {
            return false;
        }

        ArrayBufferWriter<byte> writer = new();
        QPackInteger.Write(writer, relativeIndex, DuplicatePrefixBits);
        encoderStreamInstruction = writer.WrittenSpan.ToArray();
        return true;
    }

    /// <summary>
    /// Applies decoder-stream instructions that acknowledge or cancel references.
    /// </summary>
    public void DecodeDecoderStream(ReadOnlySpan<byte> decoderStreamInstructions, bool endOfStream = false)
    {
        pendingDecoderStreamInstructions = Append(pendingDecoderStreamInstructions, decoderStreamInstructions);
        int index = 0;
        while (index < pendingDecoderStreamInstructions.Length)
        {
            if (!TryDecodeDecoderStreamInstruction(pendingDecoderStreamInstructions, ref index))
            {
                break;
            }
        }

        pendingDecoderStreamInstructions = SlicePending(pendingDecoderStreamInstructions, index);
        if (endOfStream && pendingDecoderStreamInstructions.Length != 0)
        {
            throw new QPackException(QPackErrorCode.DecoderStreamError, "The QPACK decoder stream ended with a partial instruction.");
        }
    }

    /// <summary>
    /// Signals that the decoder stream ended and validates that no partial instruction remains.
    /// </summary>
    public void CompleteDecoderStream()
    {
        DecodeDecoderStream([], endOfStream: true);
    }

    private static void WriteStaticIndexedField(IBufferWriter<byte> writer, int staticFieldIndex)
    {
        QPackInteger.Write(writer, checked((ulong)staticFieldIndex), StaticIndexedFieldPrefixBits, StaticIndexedFieldPrefix);
    }

    private static void WriteDynamicIndexedField(IBufferWriter<byte> writer, ulong baseIndex, ulong absoluteIndex)
    {
        ulong relativeIndex = baseIndex - absoluteIndex - 1;
        QPackInteger.Write(writer, relativeIndex, StaticIndexedFieldPrefixBits, DynamicIndexedFieldPrefix);
    }

    private static void WriteLiteralWithStaticNameReference(IBufferWriter<byte> writer, int staticNameIndex, string value)
    {
        QPackInteger.Write(
            writer,
            checked((ulong)staticNameIndex),
            StaticNameReferencePrefixBits,
            LiteralWithStaticNameReferencePrefix);
        QPackStringLiteral.Write(writer, value, ValueStringPrefixBits);
    }

    private static void WriteLiteralWithDynamicNameReference(
        IBufferWriter<byte> writer,
        ulong baseIndex,
        ulong absoluteIndex,
        string value)
    {
        ulong relativeIndex = baseIndex - absoluteIndex - 1;
        QPackInteger.Write(writer, relativeIndex, DynamicNameReferencePrefixBits, LiteralWithDynamicNameReferencePrefix);
        QPackStringLiteral.Write(writer, value, ValueStringPrefixBits);
    }

    private static void WriteLiteralWithLiteralName(IBufferWriter<byte> writer, QPackFieldLine fieldLine)
    {
        QPackStringLiteral.Write(writer, fieldLine.Name, LiteralNamePrefixBits, LiteralWithLiteralNamePrefix);
        QPackStringLiteral.Write(writer, fieldLine.Value, ValueStringPrefixBits);
    }

    private static void ValidateFieldLine(QPackFieldLine fieldLine)
    {
        if (string.IsNullOrEmpty(fieldLine.Name))
        {
            throw new ArgumentException("QPACK field names must not be empty.", nameof(fieldLine));
        }
    }

    private void WriteFieldSectionPrefix(IBufferWriter<byte> writer, ulong requiredInsertCount, ulong baseIndex)
    {
        ulong encodedInsertCount = EncodeRequiredInsertCount(requiredInsertCount);
        QPackInteger.Write(writer, encodedInsertCount, FieldSectionRequiredInsertCountPrefixBits);
        if (requiredInsertCount == 0)
        {
            QPackInteger.Write(writer, 0, FieldSectionBasePrefixBits);
            return;
        }

        if (baseIndex >= requiredInsertCount)
        {
            QPackInteger.Write(writer, baseIndex - requiredInsertCount, FieldSectionBasePrefixBits);
        }
        else
        {
            QPackInteger.Write(writer, requiredInsertCount - baseIndex - 1, FieldSectionBasePrefixBits, FieldSectionBaseSignPrefix);
        }
    }

    private bool TryDecodeDecoderStreamInstruction(ReadOnlySpan<byte> source, ref int index)
    {
        byte first = source[index];
        if ((first & DecoderStreamSectionAcknowledgmentMask) != 0)
        {
            return TryDecodeSectionAcknowledgment(source, ref index);
        }

        if ((first & DecoderStreamTwoBitMask) == DecoderStreamCancellationPattern)
        {
            return TryDecodeStreamCancellation(source, ref index);
        }

        return TryDecodeInsertCountIncrement(source, ref index);
    }

    private bool TryDecodeSectionAcknowledgment(ReadOnlySpan<byte> source, ref int index)
    {
        int localIndex = index;
        if (!TryReadInteger(source, ref localIndex, DecoderStreamSectionAcknowledgmentPrefixBits, out ulong streamId))
        {
            return false;
        }

        AcknowledgeSection(streamId);
        index = localIndex;
        return true;
    }

    private bool TryDecodeStreamCancellation(ReadOnlySpan<byte> source, ref int index)
    {
        int localIndex = index;
        if (!TryReadInteger(source, ref localIndex, DecoderStreamCancellationPrefixBits, out ulong streamId))
        {
            return false;
        }

        CancelStream(streamId);
        index = localIndex;
        return true;
    }

    private bool TryDecodeInsertCountIncrement(ReadOnlySpan<byte> source, ref int index)
    {
        int localIndex = index;
        if (!TryReadInteger(source, ref localIndex, DecoderStreamInsertCountIncrementPrefixBits, out ulong increment))
        {
            return false;
        }

        IncrementKnownReceivedCount(increment);
        index = localIndex;
        return true;
    }

    private static bool TryReadInteger(ReadOnlySpan<byte> source, ref int index, int prefixBitCount, out ulong value)
    {
        value = default;
        if (index >= source.Length)
        {
            return false;
        }

        if (TryReadIntegerPartial(source[index..], prefixBitCount, out value, out int bytesConsumed))
        {
            index += bytesConsumed;
            return true;
        }

        return false;
    }

    private static bool TryReadIntegerPartial(
        ReadOnlySpan<byte> source,
        int prefixBitCount,
        out ulong value,
        out int bytesConsumed)
    {
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
            ulong segment = (ulong)(next & ContinuationValueMask);
            if (shift >= MaximumContinuationShift || (segment << shift) > QPackInteger.MaxValue - value)
            {
                throw new QPackException(QPackErrorCode.DecoderStreamError, "The QPACK prefixed integer is malformed.");
            }

            value += segment << shift;
            if ((next & ContinuationFlag) == 0)
            {
                if (value > QPackInteger.MaxValue)
                {
                    throw new QPackException(QPackErrorCode.DecoderStreamError, "The QPACK prefixed integer is malformed.");
                }

                return true;
            }

            shift += ContinuationShift;
        }

        return false;
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

    private ulong EncodeRequiredInsertCount(ulong requiredInsertCount)
    {
        if (requiredInsertCount == 0)
        {
            return 0;
        }

        ulong maxEntries = checked((ulong)dynamicTable.MaximumCapacity) / MinimumDynamicTableEntrySize;
        if (maxEntries == 0)
        {
            throw new QPackException(QPackErrorCode.DecompressionFailed, "The QPACK dynamic table cannot be referenced with zero maximum capacity.");
        }

        return (requiredInsertCount % (RequiredInsertCountModuloMultiplier * maxEntries)) + 1;
    }

    private bool CanReferenceDynamicEntry(ulong absoluteIndex, HashSet<ulong> pendingReferences)
    {
        if (absoluteIndex >= dynamicTable.InsertCount)
        {
            return false;
        }

        if (absoluteIndex < KnownReceivedCount)
        {
            return true;
        }

        return blockedStreamRiskCount < maximumBlockedStreams || pendingReferences.Count > 0;
    }

    private void TrackOutstandingReferences(ulong streamId, ulong requiredInsertCount, HashSet<ulong> referencedEntries)
    {
        foreach (ulong absoluteIndex in referencedEntries)
        {
            outstandingReferenceCounts.TryGetValue(absoluteIndex, out int count);
            outstandingReferenceCounts[absoluteIndex] = count + 1;
        }

        if (!outstandingFieldSectionsByStream.TryGetValue(streamId, out Queue<OutstandingFieldSection>? sections))
        {
            sections = new Queue<OutstandingFieldSection>();
            outstandingFieldSectionsByStream.Add(streamId, sections);
        }

        sections.Enqueue(new OutstandingFieldSection(requiredInsertCount, [.. referencedEntries]));
        if (requiredInsertCount > KnownReceivedCount)
        {
            blockedStreamRiskCount++;
        }
    }

    private void AcknowledgeSection(ulong streamId)
    {
        if (!outstandingFieldSectionsByStream.TryGetValue(streamId, out Queue<OutstandingFieldSection>? sections)
            || sections.Count == 0)
        {
            throw new QPackException(QPackErrorCode.DecoderStreamError, "The QPACK section acknowledgment is invalid.");
        }

        OutstandingFieldSection section = sections.Dequeue();
        ReleaseReferences(section);
        if (section.RequiredInsertCount > KnownReceivedCount)
        {
            KnownReceivedCount = section.RequiredInsertCount;
            RecalculateBlockedStreamRiskCount();
        }
    }

    private void CancelStream(ulong streamId)
    {
        if (!outstandingFieldSectionsByStream.Remove(streamId, out Queue<OutstandingFieldSection>? sections))
        {
            return;
        }

        while (sections.Count > 0)
        {
            OutstandingFieldSection section = sections.Dequeue();
            ReleaseReferences(section);
            if (section.RequiredInsertCount > KnownReceivedCount)
            {
                RecalculateBlockedStreamRiskCount();
            }
        }
    }

    private void IncrementKnownReceivedCount(ulong increment)
    {
        if (increment == 0 || increment > dynamicTable.InsertCount - KnownReceivedCount)
        {
            throw new QPackException(QPackErrorCode.DecoderStreamError, "The QPACK Insert Count Increment is invalid.");
        }

        KnownReceivedCount += increment;
        RecalculateBlockedStreamRiskCount();
    }

    private void ReleaseReferences(OutstandingFieldSection section)
    {
        foreach (ulong absoluteIndex in section.ReferencedEntries)
        {
            int count = outstandingReferenceCounts[absoluteIndex];
            if (count == 1)
            {
                outstandingReferenceCounts.Remove(absoluteIndex);
            }
            else
            {
                outstandingReferenceCounts[absoluteIndex] = count - 1;
            }
        }
    }

    private bool IsEvictable(QPackDynamicTableEntry entry)
    {
        return entry.AbsoluteIndex < KnownReceivedCount
            && !outstandingReferenceCounts.ContainsKey(entry.AbsoluteIndex);
    }

    private void RecalculateBlockedStreamRiskCount()
    {
        int count = 0;
        foreach (Queue<OutstandingFieldSection> sections in outstandingFieldSectionsByStream.Values)
        {
            foreach (OutstandingFieldSection section in sections)
            {
                if (section.RequiredInsertCount > KnownReceivedCount)
                {
                    count++;
                }
            }
        }

        blockedStreamRiskCount = count;
    }

    private sealed record OutstandingFieldSection(ulong RequiredInsertCount, ulong[] ReferencedEntries);
}
