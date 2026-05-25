using System.Text;

namespace Incursa.Qpack;

/// <summary>
/// Maintains QPACK dynamic table state and index translation.
/// </summary>
public sealed class QPackDynamicTable
{
    private const int EntryOverhead = 32;

    private readonly List<QPackDynamicTableEntry> entries = [];

    /// <summary>
    /// Initializes a new instance of the <see cref="QPackDynamicTable" /> class.
    /// </summary>
    public QPackDynamicTable(int maximumCapacity = int.MaxValue)
    {
        if (maximumCapacity < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumCapacity));
        }

        MaximumCapacity = maximumCapacity;
    }

    /// <summary>
    /// Gets the maximum capacity permitted by local configuration.
    /// </summary>
    public int MaximumCapacity { get; }

    /// <summary>
    /// Gets the current dynamic table capacity.
    /// </summary>
    public int Capacity { get; private set; }

    /// <summary>
    /// Gets the current dynamic table size.
    /// </summary>
    public int CurrentSize { get; private set; }

    /// <summary>
    /// Gets the total number of inserts and duplications performed.
    /// </summary>
    public ulong InsertCount { get; private set; }

    /// <summary>
    /// Gets the number of entries dropped from the dynamic table.
    /// </summary>
    public ulong DroppedCount { get; private set; }

    /// <summary>
    /// Gets the number of entries currently stored in the dynamic table.
    /// </summary>
    public int Count => entries.Count;

    /// <summary>
    /// Computes the RFC 9204 dynamic table size for a field line.
    /// </summary>
    public static int GetEntrySize(QPackFieldLine fieldLine)
    {
        return checked(Encoding.Latin1.GetByteCount(fieldLine.Name) + Encoding.Latin1.GetByteCount(fieldLine.Value) + EntryOverhead);
    }

    /// <summary>
    /// Sets the table capacity and evicts entries if permitted.
    /// </summary>
    public bool TrySetCapacity(int capacity, Predicate<QPackDynamicTableEntry>? canEvict = null)
    {
        if (capacity < 0 || capacity > MaximumCapacity)
        {
            return false;
        }

        if (!CanEvictToSize(capacity, canEvict))
        {
            return false;
        }

        Capacity = capacity;
        EvictToSize(capacity);
        return true;
    }

    /// <summary>
    /// Tries to insert a new dynamic table entry.
    /// </summary>
    public bool TryInsert(
        QPackFieldLine fieldLine,
        out QPackDynamicTableEntry inserted,
        Predicate<QPackDynamicTableEntry>? canEvict = null)
    {
        inserted = default;
        int entrySize = GetEntrySize(fieldLine);
        if (entrySize > Capacity || !CanEvictToSize(Capacity - entrySize, canEvict))
        {
            return false;
        }

        EvictToSize(Capacity - entrySize);
        inserted = new QPackDynamicTableEntry(InsertCount, fieldLine, entrySize);
        entries.Add(inserted);
        CurrentSize += entrySize;
        InsertCount++;
        return true;
    }

    /// <summary>
    /// Tries to duplicate an existing dynamic table entry.
    /// </summary>
    public bool TryDuplicate(
        ulong relativeIndex,
        out QPackDynamicTableEntry inserted,
        Predicate<QPackDynamicTableEntry>? canEvict = null)
    {
        inserted = default;
        if (!TryGetByEncoderRelativeIndex(relativeIndex, out QPackDynamicTableEntry source))
        {
            return false;
        }

        return TryInsert(source.FieldLine, out inserted, canEvict);
    }

    /// <summary>
    /// Tries to get a dynamic table entry by absolute index.
    /// </summary>
    public bool TryGetByAbsoluteIndex(ulong absoluteIndex, out QPackDynamicTableEntry entry)
    {
        if (absoluteIndex < DroppedCount || absoluteIndex >= InsertCount)
        {
            entry = default;
            return false;
        }

        ulong offset = absoluteIndex - DroppedCount;
        if (offset > int.MaxValue || offset >= (ulong)entries.Count)
        {
            entry = default;
            return false;
        }

        entry = entries[(int)offset];
        return true;
    }

    /// <summary>
    /// Tries to get a dynamic table entry by encoder-stream relative index.
    /// </summary>
    public bool TryGetByEncoderRelativeIndex(ulong relativeIndex, out QPackDynamicTableEntry entry)
    {
        if (relativeIndex >= InsertCount)
        {
            entry = default;
            return false;
        }

        ulong absoluteIndex = InsertCount - relativeIndex - 1;
        return TryGetByAbsoluteIndex(absoluteIndex, out entry);
    }

    /// <summary>
    /// Tries to get a dynamic table entry by field-section relative index.
    /// </summary>
    public bool TryGetByRelativeIndex(ulong baseIndex, ulong relativeIndex, out QPackDynamicTableEntry entry)
    {
        if (baseIndex == 0 || relativeIndex >= baseIndex)
        {
            entry = default;
            return false;
        }

        ulong absoluteIndex = baseIndex - relativeIndex - 1;
        return TryGetByAbsoluteIndex(absoluteIndex, out entry);
    }

    /// <summary>
    /// Tries to get a dynamic table entry by field-section post-Base index.
    /// </summary>
    public bool TryGetByPostBaseIndex(ulong baseIndex, ulong postBaseIndex, out QPackDynamicTableEntry entry)
    {
        if (baseIndex > ulong.MaxValue - postBaseIndex)
        {
            entry = default;
            return false;
        }

        return TryGetByAbsoluteIndex(baseIndex + postBaseIndex, out entry);
    }

    internal int FindFieldLineAbsoluteIndex(QPackFieldLine fieldLine)
    {
        for (int index = entries.Count - 1; index >= 0; index--)
        {
            QPackDynamicTableEntry entry = entries[index];
            if (StringComparer.Ordinal.Equals(entry.FieldLine.Name, fieldLine.Name)
                && StringComparer.Ordinal.Equals(entry.FieldLine.Value, fieldLine.Value))
            {
                return checked((int)entry.AbsoluteIndex);
            }
        }

        return -1;
    }

    internal int FindNameAbsoluteIndex(string name)
    {
        for (int index = entries.Count - 1; index >= 0; index--)
        {
            QPackDynamicTableEntry entry = entries[index];
            if (StringComparer.Ordinal.Equals(entry.FieldLine.Name, name))
            {
                return checked((int)entry.AbsoluteIndex);
            }
        }

        return -1;
    }

    private bool CanEvictToSize(int targetSize, Predicate<QPackDynamicTableEntry>? canEvict)
    {
        int size = CurrentSize;
        foreach (QPackDynamicTableEntry entry in entries)
        {
            if (size <= targetSize)
            {
                return true;
            }

            if (canEvict is not null && !canEvict(entry))
            {
                return false;
            }

            size -= entry.Size;
        }

        return size <= targetSize;
    }

    private void EvictToSize(int targetSize)
    {
        while (CurrentSize > targetSize && entries.Count > 0)
        {
            QPackDynamicTableEntry entry = entries[0];
            entries.RemoveAt(0);
            CurrentSize -= entry.Size;
            DroppedCount = entry.AbsoluteIndex + 1;
        }
    }
}
