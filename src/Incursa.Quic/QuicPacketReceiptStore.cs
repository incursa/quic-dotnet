// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers;

namespace Incursa.Quic;

internal sealed class QuicPacketReceiptStore
{
    private readonly int initialCapacity;
    private ulong[]? packetNumbers;
    private QuicPacketReceipt[]? receipts;
    private int count;

    internal QuicPacketReceiptStore(int initialCapacity)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(initialCapacity);
        this.initialCapacity = initialCapacity;
    }

    internal int Count => count;

    internal ulong GetPacketNumber(int index)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(index);
        if (index >= count)
        {
            throw new ArgumentOutOfRangeException(nameof(index));
        }

        return packetNumbers![index];
    }

    internal QuicPacketReceipt GetReceipt(int index)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(index);
        if (index >= count)
        {
            throw new ArgumentOutOfRangeException(nameof(index));
        }

        return receipts![index];
    }

    internal void Set(ulong packetNumber, QuicPacketReceipt receipt)
    {
        int index = FindIndex(packetNumber);
        if (index >= 0)
        {
            receipts![index] = receipt;
            return;
        }

        int insertionIndex = ~index;
        EnsureCapacity(count + 1);
        if (insertionIndex < count)
        {
            Array.Copy(packetNumbers!, insertionIndex, packetNumbers!, insertionIndex + 1, count - insertionIndex);
            Array.Copy(receipts!, insertionIndex, receipts!, insertionIndex + 1, count - insertionIndex);
        }

        packetNumbers![insertionIndex] = packetNumber;
        receipts![insertionIndex] = receipt;
        count++;
    }

    internal bool TryGetValue(ulong packetNumber, out QuicPacketReceipt receipt)
    {
        int index = FindIndex(packetNumber);
        if (index < 0)
        {
            receipt = default;
            return false;
        }

        receipt = receipts![index];
        return true;
    }

    internal int RemoveRange(ulong smallest, ulong largest)
    {
        if (count == 0 || smallest > largest)
        {
            return 0;
        }

        int firstIndex = FindFirstAtLeast(smallest);
        if (firstIndex == count || packetNumbers![firstIndex] > largest)
        {
            return 0;
        }

        int lastExclusive = FindFirstGreaterThan(largest, firstIndex);
        int removedCount = lastExclusive - firstIndex;
        int trailingCount = count - lastExclusive;
        if (trailingCount > 0)
        {
            Array.Copy(packetNumbers, lastExclusive, packetNumbers, firstIndex, trailingCount);
            Array.Copy(receipts!, lastExclusive, receipts!, firstIndex, trailingCount);
        }

        int newCount = count - removedCount;
        Array.Clear(packetNumbers, newCount, removedCount);
        Array.Clear(receipts!, newCount, removedCount);
        count = newCount;
        return removedCount;
    }

    internal void ClearAndReturnStorage()
    {
        ulong[]? packetNumberStorage = packetNumbers;
        QuicPacketReceipt[]? receiptStorage = receipts;
        packetNumbers = null;
        receipts = null;
        count = 0;

        if (packetNumberStorage is not null)
        {
            ArrayPool<ulong>.Shared.Return(packetNumberStorage);
        }

        if (receiptStorage is not null)
        {
            ArrayPool<QuicPacketReceipt>.Shared.Return(receiptStorage);
        }
    }

    private int FindIndex(ulong packetNumber)
    {
        int low = 0;
        int high = count - 1;
        while (low <= high)
        {
            int middle = low + ((high - low) >> 1);
            ulong middlePacketNumber = packetNumbers![middle];
            if (middlePacketNumber == packetNumber)
            {
                return middle;
            }

            if (middlePacketNumber < packetNumber)
            {
                low = middle + 1;
            }
            else
            {
                high = middle - 1;
            }
        }

        return ~low;
    }

    private int FindFirstAtLeast(ulong packetNumber)
    {
        int low = 0;
        int high = count;
        while (low < high)
        {
            int middle = low + ((high - low) >> 1);
            if (packetNumbers![middle] < packetNumber)
            {
                low = middle + 1;
            }
            else
            {
                high = middle;
            }
        }

        return low;
    }

    private int FindFirstGreaterThan(ulong packetNumber, int low)
    {
        int high = count;
        while (low < high)
        {
            int middle = low + ((high - low) >> 1);
            if (packetNumbers![middle] <= packetNumber)
            {
                low = middle + 1;
            }
            else
            {
                high = middle;
            }
        }

        return low;
    }

    private void EnsureCapacity(int requiredCapacity)
    {
        if (packetNumbers is not null && requiredCapacity <= packetNumbers.Length)
        {
            return;
        }

        int currentCapacity = packetNumbers?.Length ?? 0;
        int doubledCapacity = currentCapacity <= int.MaxValue / 2 ? currentCapacity * 2 : int.MaxValue;
        int requestedCapacity = Math.Max(requiredCapacity, Math.Max(initialCapacity, doubledCapacity));
        ulong[] newPacketNumbers = ArrayPool<ulong>.Shared.Rent(requestedCapacity);
        QuicPacketReceipt[] newReceipts;
        try
        {
            newReceipts = ArrayPool<QuicPacketReceipt>.Shared.Rent(requestedCapacity);
        }
        catch
        {
            ArrayPool<ulong>.Shared.Return(newPacketNumbers);
            throw;
        }

        if (count > 0)
        {
            packetNumbers!.AsSpan(0, count).CopyTo(newPacketNumbers);
            receipts!.AsSpan(0, count).CopyTo(newReceipts);
        }

        ulong[]? oldPacketNumbers = packetNumbers;
        QuicPacketReceipt[]? oldReceipts = receipts;
        packetNumbers = newPacketNumbers;
        receipts = newReceipts;
        if (oldPacketNumbers is not null)
        {
            ArrayPool<ulong>.Shared.Return(oldPacketNumbers);
        }

        if (oldReceipts is not null)
        {
            ArrayPool<QuicPacketReceipt>.Shared.Return(oldReceipts);
        }
    }
}
