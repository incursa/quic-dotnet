// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S17P3P1_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0003")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0008")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0012")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0014")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0019")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0022")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ShortHeaderControlBitsRoundTripAndRejectInvalidFixedBit()
    {
        Random random = new(0x17_03_01);

        for (int iteration = 0; iteration < 128; iteration++)
        {
            byte packetNumberLengthBits = (byte)random.Next(0, 4);
            bool keyPhase = random.Next(0, 2) == 1;
            bool spinBit = random.Next(0, 2) == 1;
            byte headerControlBits = (byte)(
                (spinBit ? 0x20 : 0x00)
                | (keyPhase ? 0x04 : 0x00)
                | packetNumberLengthBits);
            byte[] remainder = QuicHeaderTestData.RandomBytes(random, random.Next(0, 32));
            byte[] packet = QuicHeaderTestData.BuildShortHeader(headerControlBits, remainder);

            Assert.True(QuicPacketParser.TryClassifyHeaderForm(packet, out QuicHeaderForm headerForm));
            Assert.Equal(QuicHeaderForm.Short, headerForm);
            Assert.True(QuicPacketParser.TryParseShortHeader(packet, out QuicShortHeaderPacket header));
            Assert.Equal(QuicHeaderForm.Short, header.HeaderForm);
            Assert.Equal(0, packet[0] & QuicPacketHeaderBits.HeaderFormBitMask);
            Assert.True(header.FixedBit);
            Assert.Equal(keyPhase, header.KeyPhase);
            Assert.Equal(packetNumberLengthBits, header.PacketNumberLengthBits);
            Assert.Equal(packetNumberLengthBits + 1, header.PacketNumberLengthBits + 1);

            byte[] invalidFixedBitPacket = packet.ToArray();
            invalidFixedBitPacket[0] = (byte)(invalidFixedBitPacket[0] & ~QuicPacketHeaderBits.FixedBitMask);
            Assert.False(QuicPacketParser.TryParseShortHeader(invalidFixedBitPacket, out _));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0002")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0009")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0010")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0011")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0021")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0023")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ProtectedApplicationDataShortHeaderBoundariesRoundTrip()
    {
        QuicTlsPacketProtectionMaterial material = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt);

        foreach (byte[] destinationConnectionId in new[]
        {
            [],
            QuicS17P2P3TestSupport.PacketConnectionId,
            QuicS12P3TestSupport.CreateSequentialBytes(0x10, 20),
        })
        {
            QuicHandshakeFlowCoordinator coordinator = new(destinationConnectionId, ReadOnlyMemory<byte>.Empty);
            byte[] payload = QuicS12P3TestSupport.CreateSequentialBytes((byte)(0x40 + destinationConnectionId.Length), 8);

            Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
                payload,
                material,
                out ulong packetNumber,
                out byte[] protectedPacket));
            Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
                protectedPacket,
                material,
                out byte[] openedPacket,
                out int payloadOffset,
                out int payloadLength));

            Assert.True(QuicPacketParser.TryParseShortHeader(openedPacket, out QuicShortHeaderPacket header));
            Assert.Equal(QuicHeaderForm.Short, header.HeaderForm);
            Assert.Equal(4, header.PacketNumberLengthBits + 1);
            Assert.True(openedPacket.AsSpan(1, destinationConnectionId.Length).SequenceEqual(destinationConnectionId));
            Assert.Equal(1 + destinationConnectionId.Length + 4, payloadOffset);
            Assert.Equal(packetNumber, QuicS17P1TestSupport.ReadPacketNumber(openedPacket.AsSpan(payloadOffset - 4, 4)));
            Assert.True(payloadLength >= payload.Length);
            Assert.True(openedPacket.AsSpan(payloadOffset, payload.Length).SequenceEqual(payload));
        }

        foreach (int packetNumberLength in new[] { 1, 2, 3, 4 })
        {
            QuicHandshakeFlowCoordinator coordinator = QuicS17P2P3TestSupport.CreatePacketCoordinator();
            byte[] payload = QuicS12P3TestSupport.CreatePingPayload();
            byte[] packetNumber = QuicS17P2P3TestSupport.CreatePacketNumber(packetNumberLength);
            byte[] protectedPacket = QuicS17P3P1TestSupport.CreateProtectedApplicationDataPacket(
                QuicS17P2P3TestSupport.PacketConnectionId,
                packetNumber,
                payload,
                material,
                declaredPacketNumberLength: packetNumberLength);

            Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
                protectedPacket,
                material,
                out byte[] openedPacket,
                out int payloadOffset,
                out int payloadLength));
            Assert.True(QuicPacketParser.TryParseShortHeader(openedPacket, out QuicShortHeaderPacket header));
            Assert.Equal(packetNumberLength, header.PacketNumberLengthBits + 1);
            Assert.Equal(1 + QuicS17P2P3TestSupport.PacketConnectionId.Length + packetNumberLength, payloadOffset);
            Assert.Equal(QuicS17P1TestSupport.ReadPacketNumber(packetNumber), QuicS17P1TestSupport.ReadPacketNumber(
                openedPacket.AsSpan(payloadOffset - packetNumberLength, packetNumberLength)));
            Assert.True(payloadLength >= payload.Length);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0018")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ProtectedApplicationDataRejectsPostProtectionTampering()
    {
        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P3TestSupport.CreatePacketCoordinator();
        QuicTlsPacketProtectionMaterial material = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt);

        foreach (int packetNumberLength in new[] { 1, 2, 4 })
        {
            byte[] protectedPacket = QuicS17P3P1TestSupport.CreateProtectedApplicationDataPacket(
                QuicS17P2P3TestSupport.PacketConnectionId,
                QuicS17P2P3TestSupport.CreatePacketNumber(packetNumberLength),
                QuicS12P3TestSupport.CreatePingPayload(),
                material,
                declaredPacketNumberLength: packetNumberLength);
            Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
                protectedPacket,
                material,
                out _,
                out _,
                out _));

            byte[] tamperedPacket = protectedPacket.ToArray();
            tamperedPacket[^1] ^= 0x01;

            Assert.False(coordinator.TryOpenProtectedApplicationDataPacket(
                tamperedPacket,
                material,
                out _,
                out _,
                out _));
        }
    }
}
