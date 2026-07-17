// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class QuicPacketReceiptStoreTests
{
    [Fact]
    public void SetMaintainsOrderAcrossGrowthAndReplacesExistingReceipts()
    {
        QuicPacketReceiptStore store = new(initialCapacity: 2);
        try
        {
            for (ulong packetNumber = 64; packetNumber > 0; packetNumber--)
            {
                store.Set(packetNumber, CreateReceipt(packetNumber));
            }

            store.Set(32, CreateReceipt(3_200));

            Assert.Equal(64, store.Count);
            Assert.Equal(1, store.RangeCount);
            for (int index = 0; index < store.Count; index++)
            {
                Assert.Equal((ulong)index + 1, store.GetPacketNumber(index));
            }

            Assert.True(store.TryGetValue(32, out QuicPacketReceipt replaced));
            Assert.Equal(3_200UL, replaced.ReceivedAtMicros);
            Assert.Equal(0, store.FindFirstIndexGreaterThan(0));
            Assert.Equal(32, store.FindFirstIndexGreaterThan(32));
            Assert.Equal(64, store.FindFirstIndexGreaterThan(64));
            Assert.Equal(64, store.FindFirstIndexGreaterThan(ulong.MaxValue));
        }
        finally
        {
            store.ClearAndReturnStorage();
        }
    }

    [Fact]
    public void RemoveRangeRemovesOnlyPresentPacketNumbersAndCompactsStorage()
    {
        QuicPacketReceiptStore store = new(initialCapacity: 4);
        try
        {
            foreach (ulong packetNumber in new ulong[] { 1, 2, 4, 7, 8, 10 })
            {
                store.Set(packetNumber, CreateReceipt(packetNumber));
            }

            Assert.Equal(3, store.RemoveRange(2, 7));
            Assert.Equal(3, store.Count);
            Assert.Equal(3, store.RangeCount);
            Assert.Equal(1UL, store.GetPacketNumber(0));
            Assert.Equal(8UL, store.GetPacketNumber(1));
            Assert.Equal(10UL, store.GetPacketNumber(2));
            Assert.Equal(0, store.RemoveRange(2, 7));
            Assert.Equal(3, store.RangeCount);
        }
        finally
        {
            store.ClearAndReturnStorage();
        }
    }

    [Fact]
    public void ClearReturnsStorageAndAllowsFreshUse()
    {
        QuicPacketReceiptStore store = new(initialCapacity: 2);
        store.Set(9, CreateReceipt(9));

        store.ClearAndReturnStorage();
        store.Set(3, CreateReceipt(3));

        Assert.Equal(1, store.Count);
        Assert.Equal(1, store.RangeCount);
        Assert.Equal(3UL, store.GetPacketNumber(0));
        store.ClearAndReturnStorage();
    }

    [Fact]
    public void SetAndRemoveRangeHandleUInt64Boundaries()
    {
        QuicPacketReceiptStore store = new(initialCapacity: 2);
        try
        {
            store.Set(ulong.MaxValue, CreateReceipt(3));
            store.Set(0, CreateReceipt(1));
            store.Set(ulong.MaxValue - 1, CreateReceipt(2));

            Assert.Equal(3, store.Count);
            Assert.Equal(2, store.RangeCount);
            Assert.Equal(0UL, store.GetPacketNumber(0));
            Assert.Equal(ulong.MaxValue - 1, store.GetPacketNumber(1));
            Assert.Equal(ulong.MaxValue, store.GetPacketNumber(2));
            Assert.Equal(2, store.RemoveRange(ulong.MaxValue - 1, ulong.MaxValue));
            Assert.Equal(0UL, store.GetPacketNumber(0));
            Assert.Equal(1, store.RangeCount);
        }
        finally
        {
            store.ClearAndReturnStorage();
        }
    }

    [Fact]
    public void SetTracksRangeMergesAcrossOutOfOrderInsertions()
    {
        QuicPacketReceiptStore store = new(initialCapacity: 2);
        try
        {
            store.Set(1, CreateReceipt(1));
            store.Set(3, CreateReceipt(3));
            Assert.Equal(2, store.RangeCount);

            store.Set(2, CreateReceipt(2));
            Assert.Equal(1, store.RangeCount);

            store.Set(5, CreateReceipt(5));
            store.Set(6, CreateReceipt(6));
            Assert.Equal(2, store.RangeCount);

            store.Set(4, CreateReceipt(4));
            Assert.Equal(1, store.RangeCount);

            store.Set(4, CreateReceipt(40));
            Assert.Equal(1, store.RangeCount);
        }
        finally
        {
            store.ClearAndReturnStorage();
        }
    }

    private static QuicPacketReceipt CreateReceipt(ulong receivedAtMicros)
        => new(receivedAtMicros, BufferingDelayMicros: 0, AckEliciting: true);
}
