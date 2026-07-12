// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Runtime.CompilerServices;

namespace Incursa.Quic.Tests;

public sealed class QuicRecoverySentPacketStateLayoutTests
{
    [Fact]
    public void LayoutRemainsCompact()
    {
        Assert.Equal(24, Unsafe.SizeOf<QuicRecoverySentPacketState>());
    }

    [Fact]
    public void ValuesRoundTripWithoutSentinels()
    {
        QuicRecoverySentPacketState state = new(
            ulong.MaxValue,
            (QuicTlsEncryptionLevel)int.MinValue,
            ulong.MaxValue);

        Assert.Equal(ulong.MaxValue, state.SentAtMicros);
        Assert.Equal((QuicTlsEncryptionLevel)int.MinValue, state.PacketProtectionLevel);
        Assert.Equal(ulong.MaxValue, state.OneRttKeyPhase);

        (ulong sentAtMicros, QuicTlsEncryptionLevel? protectionLevel, ulong? keyPhase) = state;
        Assert.Equal(state.SentAtMicros, sentAtMicros);
        Assert.Equal(state.PacketProtectionLevel, protectionLevel);
        Assert.Equal(state.OneRttKeyPhase, keyPhase);

        QuicRecoverySentPacketState absent = new(0, null, null);
        Assert.Null(absent.PacketProtectionLevel);
        Assert.Null(absent.OneRttKeyPhase);
    }

    [Fact]
    public void NullValuesRemainDistinctFromValidZeroValues()
    {
        QuicRecoverySentPacketState absent = new(1, null);
        QuicRecoverySentPacketState zeroValues = new(1, QuicTlsEncryptionLevel.Initial, 0);

        Assert.Null(absent.PacketProtectionLevel);
        Assert.Null(absent.OneRttKeyPhase);
        Assert.Equal(QuicTlsEncryptionLevel.Initial, zeroValues.PacketProtectionLevel);
        Assert.Equal(0UL, zeroValues.OneRttKeyPhase);
        Assert.NotEqual(absent, zeroValues);
    }

    [Fact]
    public void EqualityHashAndDefaultSemanticsRemainRecordCompatible()
    {
        QuicRecoverySentPacketState first = new(1, QuicTlsEncryptionLevel.OneRtt, 2);
        QuicRecoverySentPacketState equivalent = new(1, QuicTlsEncryptionLevel.OneRtt, 2);
        QuicRecoverySentPacketState different = new(1, QuicTlsEncryptionLevel.OneRtt, null);

        Assert.Equal(first, equivalent);
        Assert.Equal(first.GetHashCode(), equivalent.GetHashCode());
        Assert.NotEqual(first, different);

        QuicRecoverySentPacketState empty = default;
        Assert.Equal(0UL, empty.SentAtMicros);
        Assert.Null(empty.PacketProtectionLevel);
        Assert.Null(empty.OneRttKeyPhase);
    }
}
