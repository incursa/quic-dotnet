// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Runtime.CompilerServices;

namespace Incursa.Quic.Tests;

public sealed class QuicConnectionSentPacketLayoutTests
{
    [Fact]
    public void LayoutRemainsCompact()
    {
        int size = Unsafe.SizeOf<QuicConnectionSentPacket>();

        Assert.Equal(112, size);
    }

    [Fact]
    public void PackedPropertiesRoundTripAndWithUpdatesRemainIndependent()
    {
        byte[] packetBytes = [1, 2, 3];
        byte[] plaintextBytes = [4, 5];
        ulong[] streamIds = [ulong.MaxValue];
        QuicConnectionSentPacket packet = new(
            QuicPacketNumberSpace.ApplicationData,
            ulong.MaxValue,
            ulong.MaxValue - 1,
            ulong.MaxValue - 2,
            AckEliciting: true,
            AckOnlyPacket: true,
            ProbePacket: true,
            Retransmittable: true,
            CryptoMetadata: new QuicConnectionCryptoSendMetadata((QuicTlsEncryptionLevel)int.MaxValue),
            PacketBytes: packetBytes,
            PacketProtectionLevel: (QuicTlsEncryptionLevel)int.MinValue,
            StreamId: ulong.MaxValue,
            StreamIds: streamIds,
            PlaintextPayload: plaintextBytes,
            OneRttKeyPhase: ulong.MaxValue,
            PlaintextPayloadOwner: plaintextBytes,
            PacketBytesOwner: packetBytes);

        Assert.Equal(QuicPacketNumberSpace.ApplicationData, packet.PacketNumberSpace);
        Assert.Equal(ulong.MaxValue, packet.PacketNumber);
        Assert.Equal(ulong.MaxValue - 1, packet.PayloadBytes);
        Assert.Equal(ulong.MaxValue - 2, packet.SentAtMicros);
        Assert.True(packet.AckEliciting);
        Assert.True(packet.AckOnlyPacket);
        Assert.True(packet.ProbePacket);
        Assert.True(packet.Retransmittable);
        Assert.Equal((QuicTlsEncryptionLevel)int.MaxValue, packet.CryptoMetadata!.Value.EncryptionLevel);
        Assert.Equal((QuicTlsEncryptionLevel)int.MinValue, packet.PacketProtectionLevel);
        Assert.Equal(ulong.MaxValue, packet.StreamId);
        Assert.Same(streamIds, packet.StreamIds);
        Assert.Equal(ulong.MaxValue, packet.OneRttKeyPhase);
        Assert.Same(plaintextBytes, packet.PlaintextPayloadOwner);
        Assert.Same(packetBytes, packet.PacketBytesOwner);

        QuicConnectionSentPacket updated = packet with
        {
            Retransmittable = false,
            PacketProtectionLevel = null,
            StreamId = null,
            PacketBytes = default,
            PacketBytesOwner = null,
        };

        Assert.False(updated.Retransmittable);
        Assert.Null(updated.PacketProtectionLevel);
        Assert.Null(updated.StreamId);
        Assert.True(updated.AckEliciting);
        Assert.True(updated.AckOnlyPacket);
        Assert.True(updated.ProbePacket);
        Assert.Equal(packet.CryptoMetadata, updated.CryptoMetadata);
        Assert.Equal(packet.OneRttKeyPhase, updated.OneRttKeyPhase);
        Assert.Same(packet.PlaintextPayloadOwner, updated.PlaintextPayloadOwner);
        Assert.True(updated.PacketBytes.IsEmpty);
        Assert.Null(updated.PacketBytesOwner);

        QuicConnectionSentPacket equivalent = new(
            packet.PacketNumberSpace,
            packet.PacketNumber,
            packet.PayloadBytes,
            packet.SentAtMicros,
            AckEliciting: packet.AckEliciting,
            AckOnlyPacket: packet.AckOnlyPacket,
            ProbePacket: packet.ProbePacket,
            Retransmittable: false,
            CryptoMetadata: packet.CryptoMetadata,
            PacketBytes: default,
            PacketProtectionLevel: null,
            StreamId: null,
            StreamIds: packet.StreamIds,
            PlaintextPayload: packet.PlaintextPayload,
            OneRttKeyPhase: packet.OneRttKeyPhase,
            PlaintextPayloadOwner: packet.PlaintextPayloadOwner,
            PacketBytesOwner: null);

        Assert.Equal(equivalent, updated);
        Assert.Equal(equivalent.GetHashCode(), updated.GetHashCode());
        Assert.Contains("PacketNumberSpace = ApplicationData", updated.ToString(), StringComparison.Ordinal);
        Assert.Contains("StreamId = ", updated.ToString(), StringComparison.Ordinal);

        QuicConnectionSentPacket deconstructed = updated;
        (
            QuicPacketNumberSpace packetNumberSpace,
            ulong packetNumber,
            ulong payloadBytes,
            ulong sentAtMicros,
            bool ackEliciting,
            bool ackOnlyPacket,
            bool probePacket,
            bool retransmittable,
            QuicConnectionCryptoSendMetadata? cryptoMetadata,
            ReadOnlyMemory<byte> deconstructedPacketBytes,
            QuicTlsEncryptionLevel? deconstructedProtectionLevel,
            ulong? deconstructedStreamId,
            ulong[]? deconstructedStreamIds,
            ReadOnlyMemory<byte> plaintextPayload,
            ulong? oneRttKeyPhase,
            byte[]? plaintextPayloadOwner,
            byte[]? packetBytesOwner) = deconstructed;

        Assert.Equal(updated.PacketNumberSpace, packetNumberSpace);
        Assert.Equal(updated.PacketNumber, packetNumber);
        Assert.Equal(updated.PayloadBytes, payloadBytes);
        Assert.Equal(updated.SentAtMicros, sentAtMicros);
        Assert.Equal(updated.AckEliciting, ackEliciting);
        Assert.Equal(updated.AckOnlyPacket, ackOnlyPacket);
        Assert.Equal(updated.ProbePacket, probePacket);
        Assert.Equal(updated.Retransmittable, retransmittable);
        Assert.Equal(updated.CryptoMetadata, cryptoMetadata);
        Assert.Equal(updated.PacketBytes, deconstructedPacketBytes);
        Assert.Equal(updated.PacketProtectionLevel, deconstructedProtectionLevel);
        Assert.Equal(updated.StreamId, deconstructedStreamId);
        Assert.Same(updated.StreamIds, deconstructedStreamIds);
        Assert.Equal(updated.PlaintextPayload, plaintextPayload);
        Assert.Equal(updated.OneRttKeyPhase, oneRttKeyPhase);
        Assert.Same(updated.PlaintextPayloadOwner, plaintextPayloadOwner);
        Assert.Same(updated.PacketBytesOwner, packetBytesOwner);
    }

    [Fact]
    public void DefaultValuePreservesOriginalRecordSemantics()
    {
        QuicConnectionSentPacket packet = default;

        Assert.False(packet.AckEliciting);
        Assert.False(packet.AckOnlyPacket);
        Assert.False(packet.ProbePacket);
        Assert.False(packet.Retransmittable);
        Assert.Null(packet.CryptoMetadata);
        Assert.Null(packet.PacketProtectionLevel);
        Assert.Null(packet.StreamId);
        Assert.Null(packet.OneRttKeyPhase);
    }
}
