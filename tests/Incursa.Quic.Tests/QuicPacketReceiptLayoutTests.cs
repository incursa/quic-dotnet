// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Runtime.CompilerServices;

namespace Incursa.Quic.Tests;

public sealed class QuicPacketReceiptLayoutTests
{
    [Fact]
    public void LayoutRemainsCompact()
    {
        Assert.Equal(48, Unsafe.SizeOf<QuicPacketReceipt>());
    }

    [Fact]
    public void ValuesRoundTripWithoutSentinels()
    {
        QuicEcnCounts ecnCounts = new(ulong.MaxValue, ulong.MaxValue - 1, ulong.MaxValue - 2);
        QuicPacketReceipt receipt = new(
            ulong.MaxValue,
            ulong.MaxValue - 3,
            AckEliciting: true,
            CongestionExperienced: true,
            EcnCounts: ecnCounts);

        Assert.Equal(ulong.MaxValue, receipt.ReceivedAtMicros);
        Assert.Equal(ulong.MaxValue - 3, receipt.BufferingDelayMicros);
        Assert.True(receipt.AckEliciting);
        Assert.True(receipt.CongestionExperienced);
        Assert.Equal(ecnCounts.Ect0Count, receipt.EcnCounts!.Value.Ect0Count);
        Assert.Equal(ecnCounts.Ect1Count, receipt.EcnCounts.Value.Ect1Count);
        Assert.Equal(ecnCounts.EcnCeCount, receipt.EcnCounts.Value.EcnCeCount);

        (ulong receivedAt, ulong bufferingDelay, bool ackEliciting, bool congestionExperienced, QuicEcnCounts? deconstructedEcnCounts) = receipt;
        Assert.Equal(receipt.ReceivedAtMicros, receivedAt);
        Assert.Equal(receipt.BufferingDelayMicros, bufferingDelay);
        Assert.Equal(receipt.AckEliciting, ackEliciting);
        Assert.Equal(receipt.CongestionExperienced, congestionExperienced);
        Assert.Equal(receipt.EcnCounts!.Value.Ect0Count, deconstructedEcnCounts!.Value.Ect0Count);

        QuicPacketReceipt absent = new(0, 0, AckEliciting: false, CongestionExperienced: false, EcnCounts: null);
        Assert.Null(absent.EcnCounts);
        Assert.False(absent.AckEliciting);
        Assert.False(absent.CongestionExperienced);
    }

    [Fact]
    public void EqualityHashAndDefaultSemanticsRemainRecordCompatible()
    {
        QuicEcnCounts ecnCounts = new(1, 2, 3);
        QuicPacketReceipt first = new(4, 5, AckEliciting: true, CongestionExperienced: false, EcnCounts: ecnCounts);
        QuicPacketReceipt equivalent = new(4, 5, AckEliciting: true, CongestionExperienced: false, EcnCounts: ecnCounts);
        QuicPacketReceipt different = new(4, 5, AckEliciting: true, CongestionExperienced: false, EcnCounts: null);

        Assert.Equal(first, equivalent);
        Assert.Equal(first.GetHashCode(), equivalent.GetHashCode());
        Assert.NotEqual(first, different);

        QuicPacketReceipt empty = default;
        Assert.Equal(0UL, empty.ReceivedAtMicros);
        Assert.Equal(0UL, empty.BufferingDelayMicros);
        Assert.False(empty.AckEliciting);
        Assert.False(empty.CongestionExperienced);
        Assert.Null(empty.EcnCounts);
    }
}
