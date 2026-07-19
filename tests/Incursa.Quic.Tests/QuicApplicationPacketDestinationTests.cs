// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class QuicApplicationPacketDestinationTests
{
    private static readonly byte[] DestinationConnectionId = [0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08];

    [Fact]
    public void CallerOwnedDestination_ProducesPacketThatOpensToOriginalPayload()
    {
        byte[] payload = Enumerable.Range(0, 1400).Select(static value => (byte)value).ToArray();
        QuicTlsPacketProtectionMaterial material = CreatePacketProtectionMaterial();
        QuicHandshakeFlowCoordinator sender = new(DestinationConnectionId);
        QuicHandshakeFlowCoordinator receiver = new(DestinationConnectionId);
        byte[] destination = new byte[2048];

        Assert.True(sender.TryBuildProtectedApplicationDataPacket(
            payload,
            material,
            keyPhase: false,
            spinBit: true,
            greaseQuicBit: false,
            destination,
            out ulong packetNumber,
            out int protectedPacketLength));
        Assert.Equal(0UL, packetNumber);

        Assert.True(receiver.TryOpenProtectedApplicationDataPacket(
            destination.AsSpan(0, protectedPacketLength),
            material,
            expectedPacketNumber: packetNumber,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength));
        Assert.Equal(payload, openedPacket.AsSpan(payloadOffset, payloadLength).ToArray());
    }

    [Fact]
    public void DestinationTooSmall_DoesNotAdvancePacketNumber()
    {
        byte[] payload = new byte[1400];
        QuicTlsPacketProtectionMaterial material = CreatePacketProtectionMaterial();
        QuicHandshakeFlowCoordinator sender = new(DestinationConnectionId);

        Assert.False(sender.TryBuildProtectedApplicationDataPacket(
            payload,
            material,
            keyPhase: false,
            spinBit: true,
            greaseQuicBit: false,
            new byte[32],
            out _,
            out _));

        Assert.True(sender.TryBuildProtectedApplicationDataPacket(
            payload,
            material,
            keyPhase: false,
            spinBit: true,
            greaseQuicBit: false,
            new byte[2048],
            out ulong packetNumber,
            out _));
        Assert.Equal(0UL, packetNumber);
    }

    private static QuicTlsPacketProtectionMaterial CreatePacketProtectionMaterial()
    {
        if (!QuicTlsPacketProtectionMaterial.TryCreate(
                QuicTlsEncryptionLevel.OneRtt,
                QuicAeadAlgorithm.Aes128Gcm,
                Enumerable.Range(0x10, 16).Select(static value => (byte)value).ToArray(),
                Enumerable.Range(0x20, 12).Select(static value => (byte)value).ToArray(),
                Enumerable.Range(0x30, 16).Select(static value => (byte)value).ToArray(),
                new QuicAeadUsageLimits(1UL << 40, 1UL << 40),
                out QuicTlsPacketProtectionMaterial material))
        {
            throw new InvalidOperationException("Failed to create test packet-protection material.");
        }

        return material;
    }
}
