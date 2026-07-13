// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Runtime.CompilerServices;

namespace Incursa.Quic.Tests;

public sealed class QuicPacketReceiptLayoutTests
{
    [Fact]
    public void LayoutRemainsCompact()
    {
        Assert.Equal(24, Unsafe.SizeOf<QuicPacketReceipt>());
    }

    [Fact]
    public void ValuesRoundTripWithoutSentinels()
    {
        QuicPacketReceipt receipt = new(
            ulong.MaxValue,
            ulong.MaxValue - 3,
            AckEliciting: true);

        Assert.Equal(ulong.MaxValue, receipt.ReceivedAtMicros);
        Assert.Equal(ulong.MaxValue - 3, receipt.BufferingDelayMicros);
        Assert.True(receipt.AckEliciting);

        (ulong receivedAt, ulong bufferingDelay, bool ackEliciting) = receipt;
        Assert.Equal(receipt.ReceivedAtMicros, receivedAt);
        Assert.Equal(receipt.BufferingDelayMicros, bufferingDelay);
        Assert.Equal(receipt.AckEliciting, ackEliciting);

        QuicPacketReceipt absent = new(0, 0, AckEliciting: false);
        Assert.False(absent.AckEliciting);
    }

    [Fact]
    public void EqualityHashAndDefaultSemanticsRemainRecordCompatible()
    {
        QuicPacketReceipt first = new(4, 5, AckEliciting: true);
        QuicPacketReceipt equivalent = new(4, 5, AckEliciting: true);
        QuicPacketReceipt different = new(4, 5, AckEliciting: false);

        Assert.Equal(first, equivalent);
        Assert.Equal(first.GetHashCode(), equivalent.GetHashCode());
        Assert.NotEqual(first, different);

        QuicPacketReceipt empty = default;
        Assert.Equal(0UL, empty.ReceivedAtMicros);
        Assert.Equal(0UL, empty.BufferingDelayMicros);
        Assert.False(empty.AckEliciting);
    }
}
