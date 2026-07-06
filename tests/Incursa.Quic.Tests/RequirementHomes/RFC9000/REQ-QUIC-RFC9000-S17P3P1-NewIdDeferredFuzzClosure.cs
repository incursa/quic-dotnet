// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S17P3P1_NewIdDeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1071")]
    [Requirement("REQ-QUIC-RFC9000-1073")]
    [Requirement("REQ-QUIC-RFC9000-1075")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ShortHeaderParserPreservesZeroReservedBitsAndPacketNumberLengthBits()
    {
        Random random = new(0x17_03_01_01);

        for (int iteration = 0; iteration < 128; iteration++)
        {
            byte packetNumberLengthBits = (byte)random.Next(0, 4);
            bool keyPhase = random.Next(0, 2) == 1;
            bool spinBit = random.Next(0, 2) == 1;
            byte headerControlBits = (byte)(
                (spinBit ? 0x20 : 0x00)
                | (keyPhase ? 0x04 : 0x00)
                | packetNumberLengthBits);
            byte[] remainder = QuicHeaderTestData.RandomBytes(random, random.Next(0, 64));
            byte[] packet = QuicHeaderTestData.BuildShortHeader(headerControlBits, remainder);

            Assert.True(QuicPacketParser.TryParseShortHeader(packet, out QuicShortHeaderPacket header));
            Assert.Equal((byte)0x00, header.ReservedBits);
            Assert.Equal(packetNumberLengthBits, header.PacketNumberLengthBits);
            Assert.True(remainder.AsSpan().SequenceEqual(header.Remainder));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1071")]
    [Requirement("REQ-QUIC-RFC9000-1073")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ShortHeaderParserRejectsNonZeroReservedBits()
    {
        Random random = new(0x17_03_01_02);
        byte[] reservedBitCases = [0x08, 0x10, 0x18];

        for (int iteration = 0; iteration < 128; iteration++)
        {
            byte packetNumberLengthBits = (byte)random.Next(0, 4);
            byte reservedBits = reservedBitCases[iteration % reservedBitCases.Length];
            byte headerControlBits = (byte)(reservedBits | packetNumberLengthBits);
            byte[] packet = QuicHeaderTestData.BuildShortHeader(
                headerControlBits,
                QuicHeaderTestData.RandomBytes(random, random.Next(0, 64)));

            Assert.False(QuicPacketParser.TryParseShortHeader(packet, out _));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1059")]
    [Requirement("REQ-QUIC-RFC9000-1075")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ProtectedOneRttApplicationDataOpensAsShortHeaderWithEncodedPacketNumberLength()
    {
        QuicTlsPacketProtectionMaterial material = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt);
        Random random = new(0x17_03_01_03);

        for (int iteration = 0; iteration < 64; iteration++)
        {
            int packetNumberLength = 1 + (iteration % 4);
            byte[] destinationConnectionId = QuicHeaderTestData.RandomBytes(random, random.Next(0, 21));
            byte[] packetNumber = QuicS17P2P3TestSupport.CreatePacketNumber(packetNumberLength);
            byte[] payload = QuicHeaderTestData.RandomBytes(random, random.Next(1, 64));
            byte[] protectedPacket = QuicS17P3P1TestSupport.CreateProtectedApplicationDataPacket(
                destinationConnectionId,
                packetNumber,
                payload,
                material,
                declaredPacketNumberLength: packetNumberLength);
            QuicHandshakeFlowCoordinator coordinator = new(destinationConnectionId, ReadOnlyMemory<byte>.Empty);

            Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
                protectedPacket,
                material,
                out byte[] openedPacket,
                out int payloadOffset,
                out int payloadLength));
            Assert.True(QuicPacketParser.TryParseShortHeader(openedPacket, out QuicShortHeaderPacket header));
            Assert.Equal(QuicHeaderForm.Short, header.HeaderForm);
            Assert.Equal((byte)(packetNumberLength - 1), header.PacketNumberLengthBits);
            Assert.Equal(1 + destinationConnectionId.Length + packetNumberLength, payloadOffset);
            Assert.Equal(QuicS17P1TestSupport.ReadPacketNumber(packetNumber), QuicS17P1TestSupport.ReadPacketNumber(
                openedPacket.AsSpan(payloadOffset - packetNumberLength, packetNumberLength)));
            Assert.True(payloadLength >= payload.Length);
            Assert.True(openedPacket.AsSpan(payloadOffset, payload.Length).SequenceEqual(payload));
        }
    }
}
