// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Runtime.CompilerServices;

namespace Incursa.Quic.Tests;

public sealed class QuicRecoverySentPacketMetadataTests
{
    [Fact]
    public void LayoutRemainsCompact()
    {
        Assert.Equal(16, Unsafe.SizeOf<QuicRecoverySentPacketMetadata>());
    }

    [Fact]
    public void ValuesRoundTripWithoutSentinels()
    {
        QuicRecoverySentPacketMetadata metadata = new(
            (QuicTlsEncryptionLevel)int.MinValue,
            ulong.MaxValue);

        Assert.Equal((QuicTlsEncryptionLevel)int.MinValue, metadata.PacketProtectionLevel);
        Assert.Equal(ulong.MaxValue, metadata.OneRttKeyPhase);

        (QuicTlsEncryptionLevel? protectionLevel, ulong? keyPhase) = metadata;
        Assert.Equal(metadata.PacketProtectionLevel, protectionLevel);
        Assert.Equal(metadata.OneRttKeyPhase, keyPhase);

        QuicRecoverySentPacketMetadata absent = new(null, null);
        Assert.Null(absent.PacketProtectionLevel);
        Assert.Null(absent.OneRttKeyPhase);
    }

    [Fact]
    public void NullValuesRemainDistinctFromValidZeroValues()
    {
        QuicRecoverySentPacketMetadata absent = new(null);
        QuicRecoverySentPacketMetadata zeroValues = new(QuicTlsEncryptionLevel.Initial, 0);

        Assert.Null(absent.PacketProtectionLevel);
        Assert.Null(absent.OneRttKeyPhase);
        Assert.Equal(QuicTlsEncryptionLevel.Initial, zeroValues.PacketProtectionLevel);
        Assert.Equal(0UL, zeroValues.OneRttKeyPhase);
        Assert.NotEqual(absent, zeroValues);
    }

    [Fact]
    public void MixedApplicationProtectionLevelsRemainIndependentlyDiscardable()
    {
        QuicRecoveryController controller = new();
        controller.RecordPacketSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 1,
            sentAtMicros: 1,
            packetProtectionLevel: QuicTlsEncryptionLevel.ZeroRtt);
        controller.RecordPacketSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 2,
            sentAtMicros: 2,
            packetProtectionLevel: QuicTlsEncryptionLevel.OneRtt,
            oneRttKeyPhase: 0);

        Assert.True(controller.TryDiscardPacketProtectionLevel(QuicTlsEncryptionLevel.ZeroRtt));
        Assert.True(controller.HasAckElicitingPacketsInFlight(QuicPacketNumberSpace.ApplicationData));
        Assert.True(controller.TryDiscardPacketProtectionLevel(QuicTlsEncryptionLevel.OneRtt));
        Assert.False(controller.HasAckElicitingPacketsInFlight(QuicPacketNumberSpace.ApplicationData));
    }

    [Fact]
    public void KeyUpdateEpochsRemainIndependentlyDiscardableAcrossFullWidth()
    {
        QuicRecoveryController controller = new();
        controller.RecordPacketSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 1,
            sentAtMicros: 1,
            packetProtectionLevel: QuicTlsEncryptionLevel.OneRtt,
            oneRttKeyPhase: 0);
        controller.RecordPacketSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 2,
            sentAtMicros: 2,
            packetProtectionLevel: QuicTlsEncryptionLevel.OneRtt,
            oneRttKeyPhase: ulong.MaxValue);

        Assert.True(controller.TryDiscardOneRttKeyPhase(0));
        Assert.True(controller.HasAckElicitingPacketsInFlight(QuicPacketNumberSpace.ApplicationData));
        Assert.True(controller.TryDiscardOneRttKeyPhase(ulong.MaxValue));
        Assert.False(controller.HasAckElicitingPacketsInFlight(QuicPacketNumberSpace.ApplicationData));
    }

    [Fact]
    public void DuplicatePacketMetadataCanMoveBetweenDefaultAndNonDefaultValues()
    {
        QuicRecoveryController controller = new();
        controller.RecordPacketSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 1,
            sentAtMicros: 1,
            packetProtectionLevel: QuicTlsEncryptionLevel.OneRtt,
            oneRttKeyPhase: 0);
        controller.RecordPacketSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 2,
            sentAtMicros: 2,
            packetProtectionLevel: QuicTlsEncryptionLevel.OneRtt,
            oneRttKeyPhase: 1);

        controller.RecordPacketSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 2,
            sentAtMicros: 3,
            packetProtectionLevel: QuicTlsEncryptionLevel.OneRtt,
            oneRttKeyPhase: 0);
        Assert.False(controller.TryDiscardOneRttKeyPhase(1));

        controller.RecordPacketSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 2,
            sentAtMicros: 4,
            packetProtectionLevel: QuicTlsEncryptionLevel.OneRtt,
            oneRttKeyPhase: 1);
        Assert.True(controller.TryDiscardOneRttKeyPhase(1));
        Assert.True(controller.HasAckElicitingPacketsInFlight(QuicPacketNumberSpace.ApplicationData));
        Assert.True(controller.TryDiscardOneRttKeyPhase(0));
        Assert.False(controller.HasAckElicitingPacketsInFlight(QuicPacketNumberSpace.ApplicationData));
    }

    [Fact]
    public void DefaultMetadataResetsAfterLedgerDrains()
    {
        QuicRecoveryController controller = new();
        controller.RecordPacketSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 1,
            sentAtMicros: 1,
            packetProtectionLevel: QuicTlsEncryptionLevel.ZeroRtt);
        Assert.True(controller.TryDiscardPacketProtectionLevel(QuicTlsEncryptionLevel.ZeroRtt));

        controller.RecordPacketSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 2,
            sentAtMicros: 2,
            packetProtectionLevel: QuicTlsEncryptionLevel.OneRtt,
            oneRttKeyPhase: ulong.MaxValue);

        Assert.True(controller.TryDiscardOneRttKeyPhase(ulong.MaxValue));
        Assert.False(controller.HasAckElicitingPacketsInFlight(QuicPacketNumberSpace.ApplicationData));
    }

    [Fact]
    public void AckAndLossRemovalRemainCorrectAcrossRepeatedMetadataRebases()
    {
        QuicRecoveryController controller = new();
        controller.RecordPacketSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 1,
            sentAtMicros: 10,
            packetProtectionLevel: QuicTlsEncryptionLevel.OneRtt,
            oneRttKeyPhase: 0);
        controller.RecordPacketSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 2,
            sentAtMicros: 20,
            packetProtectionLevel: QuicTlsEncryptionLevel.OneRtt,
            oneRttKeyPhase: 1);
        controller.RecordPacketSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 3,
            sentAtMicros: 30,
            packetProtectionLevel: QuicTlsEncryptionLevel.OneRtt,
            oneRttKeyPhase: ulong.MaxValue);

        Assert.True(controller.TryDiscardOneRttKeyPhase(0));
        Assert.True(controller.RecordAcknowledgment(
            QuicPacketNumberSpace.ApplicationData,
            largestAcknowledgedPacketNumber: 2,
            ackReceivedAtMicros: 120,
            newlyAcknowledgedAckElicitingPacketNumbers: [2]));

        controller.RecordPacketSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 6,
            sentAtMicros: 60,
            packetProtectionLevel: QuicTlsEncryptionLevel.OneRtt,
            oneRttKeyPhase: ulong.MaxValue);
        Assert.True(controller.RecordAcknowledgment(
            QuicPacketNumberSpace.ApplicationData,
            largestAcknowledgedPacketNumber: 6,
            ackReceivedAtMicros: 160,
            newlyAcknowledgedAckElicitingPacketNumbers: [6]));

        IReadOnlyList<QuicLostPacket> lostPackets = controller.DetectLostPackets(
            nowMicros: 1_000,
            out _,
            out _);

        QuicLostPacket lostPacket = Assert.Single(lostPackets);
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, lostPacket.PacketNumberSpace);
        Assert.Equal(3UL, lostPacket.PacketNumber);
        Assert.False(controller.HasAckElicitingPacketsInFlight(QuicPacketNumberSpace.ApplicationData));
        Assert.False(controller.TryDiscardOneRttKeyPhase(ulong.MaxValue));
    }
}
