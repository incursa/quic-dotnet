// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S17P2P4_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P4-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_HandshakePacket_UsesLongHeaderTypeTwoWithLengthAndPacketNumberFields()
    {
        foreach (HandshakePacketCase testCase in HandshakePacketCases())
        {
            QuicLongHeaderPacket header = AssertHandshakePacketRoundTrip(testCase);
            HandshakeVersionSpecificFields fields = ParseHandshakeVersionSpecificFields(header);

            Assert.Equal((byte)QuicLongPacketTypeBits.Handshake, header.LongPacketTypeBits);
            Assert.True(fields.PayloadLengthBytes > 0);
            Assert.Equal(testCase.PacketNumberLength, fields.PacketNumber.Length);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P4-0002")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_HandshakeFirstByteContainsReservedAndPacketNumberLengthBits()
    {
        foreach (HandshakePacketCase testCase in HandshakePacketCases())
        {
            QuicLongHeaderPacket header = AssertHandshakePacketRoundTrip(testCase);

            Assert.Equal(testCase.ReservedBits, header.ReservedBits);
            Assert.Equal(testCase.PacketNumberLength - 1, header.PacketNumberLengthBits);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P4-0004")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_HandshakeHeaderFormBit_IsAlwaysLongHeader()
    {
        foreach (HandshakePacketCase testCase in HandshakePacketCases())
        {
            byte[] packet = BuildHandshakePacket(testCase);

            Assert.True(QuicPacketParser.TryClassifyHeaderForm(packet, out QuicHeaderForm headerForm));
            Assert.Equal(QuicHeaderForm.Long, headerForm);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P4-0005")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_HandshakeFixedBit_IsSetAcrossPacketNumberAndReservedBitValues()
    {
        foreach (HandshakePacketCase testCase in HandshakePacketCases())
        {
            QuicLongHeaderPacket header = AssertHandshakePacketRoundTrip(testCase);

            Assert.True(header.FixedBit);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P4-0006")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_HandshakeLongPacketTypeBits_AreTypeTwo()
    {
        foreach (HandshakePacketCase testCase in HandshakePacketCases())
        {
            QuicLongHeaderPacket header = AssertHandshakePacketRoundTrip(testCase);

            Assert.Equal((byte)0x02, header.LongPacketTypeBits);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P4-0007")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_HandshakeReservedBits_AreTwoBitsWideAndPreservedForValidation()
    {
        foreach (HandshakePacketCase testCase in HandshakePacketCases())
        {
            QuicLongHeaderPacket header = AssertHandshakePacketRoundTrip(testCase);

            Assert.InRange(header.ReservedBits, (byte)0, (byte)3);
            Assert.Equal(testCase.ReservedBits, header.ReservedBits);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P4-0008")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_HandshakePacketNumberLengthBits_EncodeOneThroughFourBytes()
    {
        foreach (HandshakePacketCase testCase in HandshakePacketCases())
        {
            QuicLongHeaderPacket header = AssertHandshakePacketRoundTrip(testCase);

            Assert.Equal(testCase.PacketNumberLength - 1, header.PacketNumberLengthBits);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P4-0009")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_HandshakeVersionField_IsThirtyTwoBitsAndVersionOne()
    {
        foreach (HandshakePacketCase testCase in HandshakePacketCases())
        {
            QuicLongHeaderPacket header = AssertHandshakePacketRoundTrip(testCase);

            Assert.Equal(QuicVersionNegotiation.Version1, header.Version);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P4-0010")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_HandshakeDestinationConnectionIdLength_IsEightBits()
    {
        foreach (HandshakePacketCase testCase in HandshakePacketCases())
        {
            QuicLongHeaderPacket header = AssertHandshakePacketRoundTrip(testCase);

            Assert.Equal(testCase.DestinationConnectionIdLength, header.DestinationConnectionIdLength);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P4-0011")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_HandshakeDestinationConnectionId_IsZeroToTwentyBytes()
    {
        foreach (HandshakePacketCase testCase in HandshakePacketCases())
        {
            QuicLongHeaderPacket header = AssertHandshakePacketRoundTrip(testCase);

            Assert.InRange(header.DestinationConnectionId.Length, 0, 20);
            Assert.Equal(testCase.DestinationConnectionIdLength, header.DestinationConnectionId.Length);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P4-0012")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_HandshakeSourceConnectionIdLength_IsEightBits()
    {
        foreach (HandshakePacketCase testCase in HandshakePacketCases())
        {
            QuicLongHeaderPacket header = AssertHandshakePacketRoundTrip(testCase);

            Assert.Equal(testCase.SourceConnectionIdLength, header.SourceConnectionIdLength);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P4-0013")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_HandshakeSourceConnectionId_IsZeroToTwentyBytes()
    {
        foreach (HandshakePacketCase testCase in HandshakePacketCases())
        {
            QuicLongHeaderPacket header = AssertHandshakePacketRoundTrip(testCase);

            Assert.InRange(header.SourceConnectionId.Length, 0, 20);
            Assert.Equal(testCase.SourceConnectionIdLength, header.SourceConnectionId.Length);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P4-0014")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_HandshakeLengthField_IsVariableLengthIntegerEncoded()
    {
        foreach (HandshakePacketCase testCase in HandshakePacketCases())
        {
            HandshakeVersionSpecificFields fields =
                ParseHandshakeVersionSpecificFields(AssertHandshakePacketRoundTrip(testCase));

            Assert.Equal((ulong)(testCase.PacketNumberLength + testCase.ProtectedPayloadLength), fields.PayloadLength);
            Assert.Equal(ExpectedVarintLength(fields.PayloadLength), fields.PayloadLengthBytes);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P4-0015")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_HandshakePacketNumberField_IsOneToFourBytesLong()
    {
        foreach (HandshakePacketCase testCase in HandshakePacketCases())
        {
            HandshakeVersionSpecificFields fields =
                ParseHandshakeVersionSpecificFields(AssertHandshakePacketRoundTrip(testCase));

            Assert.InRange(fields.PacketNumber.Length, 1, 4);
            Assert.Equal(testCase.PacketNumberLength, fields.PacketNumber.Length);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P4-0017")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_HandshakePacket_ExposesRecipientChosenDestinationAndSenderChosenSourceConnectionIds()
    {
        foreach (HandshakePacketCase testCase in HandshakePacketCases())
        {
            QuicLongHeaderPacket header = AssertHandshakePacketRoundTrip(testCase);

            Assert.True(SequentialBytes(0xD0, testCase.DestinationConnectionIdLength).AsSpan()
                .SequenceEqual(header.DestinationConnectionId));
            Assert.True(SequentialBytes(0x50, testCase.SourceConnectionIdLength).AsSpan()
                .SequenceEqual(header.SourceConnectionId));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P4-0018")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_FirstServerHandshakePacket_StartsAtPacketNumberZero()
    {
        foreach (int cryptoPayloadLength in new[] { 1, 20, 64 })
        {
            Assert.True(QuicS12P3TestSupport.TryCreatePacketProtectionMaterial(
                QuicTlsEncryptionLevel.Handshake,
                out QuicTlsPacketProtectionMaterial handshakeMaterial));

            QuicHandshakeFlowCoordinator coordinator = QuicS17P1TestSupport.CreateHandshakeCoordinator();
            byte[] cryptoPayload = SequentialBytes(0x60, cryptoPayloadLength);

            Assert.True(coordinator.TryBuildProtectedHandshakePacket(
                cryptoPayload,
                cryptoPayloadOffset: 0,
                handshakeMaterial,
                out ulong packetNumber,
                out byte[] protectedPacket));

            Assert.Equal(0UL, packetNumber);
            AssertOpenedHandshakePacketNumber(protectedPacket, handshakeMaterial, expectedPacketNumber: 0);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P4-0019")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_HandshakePayload_CarriesCryptoWithAllowedPingAndPaddingFrames()
    {
        foreach (int cryptoPayloadLength in new[] { 1, 20, 64 })
        {
            Assert.True(QuicS12P3TestSupport.TryCreatePacketProtectionMaterial(
                QuicTlsEncryptionLevel.Handshake,
                out QuicTlsPacketProtectionMaterial handshakeMaterial));

            QuicHandshakeFlowCoordinator coordinator = QuicS17P1TestSupport.CreateHandshakeCoordinator();
            byte[] cryptoPayload = SequentialBytes(0xA0, cryptoPayloadLength);
            byte[] prefixFramePayload =
            [
                .. QuicFrameTestData.BuildPingFrame(),
                .. QuicFrameTestData.BuildPaddingFrame(),
            ];

            Assert.True(coordinator.TryBuildProtectedHandshakePacket(
                cryptoPayload,
                cryptoPayloadOffset: 0,
                prefixFramePayload,
                handshakeMaterial,
                out byte[] protectedPacket));
            Assert.True(coordinator.TryOpenHandshakePacket(
                protectedPacket,
                handshakeMaterial,
                out byte[] openedPacket,
                out int payloadOffset,
                out int payloadLength));

            ReadOnlySpan<byte> payload = openedPacket.AsSpan(payloadOffset, payloadLength);
            Assert.True(QuicFrameCodec.TryParsePingFrame(payload, out int pingBytesConsumed));
            ReadOnlySpan<byte> remaining = QuicS13AckPiggybackTestSupport.SkipPadding(payload[pingBytesConsumed..]);
            Assert.True(QuicFrameCodec.TryParseCryptoFrame(remaining, out QuicCryptoFrame cryptoFrame, out _));
            Assert.True(cryptoFrame.CryptoData.SequenceEqual(cryptoPayload));
        }
    }

    private static IEnumerable<HandshakePacketCase> HandshakePacketCases()
    {
        foreach (int packetNumberLength in new[] { 1, 2, 3, 4 })
        {
            foreach (byte reservedBits in new byte[] { 0, 1, 2, 3 })
            {
                yield return new HandshakePacketCase(
                    packetNumberLength,
                    reservedBits,
                    DestinationConnectionIdLength: 0,
                    SourceConnectionIdLength: 0,
                    ProtectedPayloadLength: 1);
                yield return new HandshakePacketCase(
                    packetNumberLength,
                    reservedBits,
                    DestinationConnectionIdLength: 8,
                    SourceConnectionIdLength: 4,
                    ProtectedPayloadLength: 16);
                yield return new HandshakePacketCase(
                    packetNumberLength,
                    reservedBits,
                    DestinationConnectionIdLength: 20,
                    SourceConnectionIdLength: 20,
                    ProtectedPayloadLength: 64);
            }
        }
    }

    private static byte[] BuildHandshakePacket(HandshakePacketCase testCase)
    {
        return QuicHandshakePacketRequirementTestData.BuildHandshakePacket(
            packetNumberLength: testCase.PacketNumberLength,
            reservedBits: testCase.ReservedBits,
            destinationConnectionId: SequentialBytes(0xD0, testCase.DestinationConnectionIdLength),
            sourceConnectionId: SequentialBytes(0x50, testCase.SourceConnectionIdLength),
            protectedPayload: SequentialBytes(0xB0, testCase.ProtectedPayloadLength));
    }

    private static QuicLongHeaderPacket AssertHandshakePacketRoundTrip(HandshakePacketCase testCase)
    {
        byte[] packet = BuildHandshakePacket(testCase);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(QuicHeaderForm.Long, header.HeaderForm);
        Assert.Equal(QuicVersionNegotiation.Version1, header.Version);
        Assert.Equal((byte)QuicLongPacketTypeBits.Handshake, header.LongPacketTypeBits);
        return header;
    }

    private static HandshakeVersionSpecificFields ParseHandshakeVersionSpecificFields(QuicLongHeaderPacket header)
    {
        ReadOnlySpan<byte> versionSpecificData = header.VersionSpecificData;
        Assert.True(QuicVariableLengthInteger.TryParse(versionSpecificData, out ulong payloadLength, out int payloadLengthBytes));

        ReadOnlySpan<byte> payload = versionSpecificData[payloadLengthBytes..];
        int packetNumberLength = (header.PacketNumberLengthBits & QuicPacketHeaderBits.PacketNumberLengthBitsMask) + 1;
        ReadOnlySpan<byte> packetNumber = payload[..packetNumberLength];
        ReadOnlySpan<byte> protectedPayload = payload.Slice(
            packetNumberLength,
            checked((int)payloadLength) - packetNumberLength);

        return new HandshakeVersionSpecificFields(
            payloadLength,
            payloadLengthBytes,
            packetNumber.ToArray(),
            protectedPayload.ToArray());
    }

    private static void AssertOpenedHandshakePacketNumber(
        ReadOnlySpan<byte> protectedPacket,
        QuicTlsPacketProtectionMaterial material,
        ulong expectedPacketNumber)
    {
        QuicHandshakeFlowCoordinator coordinator = QuicS17P1TestSupport.CreateHandshakeCoordinator();

        Assert.True(coordinator.TryOpenHandshakePacket(
            protectedPacket,
            material,
            out byte[] openedPacket,
            out int payloadOffset,
            out _));
        Assert.Equal(expectedPacketNumber, QuicS17P1TestSupport.ReadPacketNumber(openedPacket.AsSpan(payloadOffset - 4, 4)));
    }

    private static int ExpectedVarintLength(ulong value)
    {
        if (value <= 63)
        {
            return 1;
        }

        if (value <= 16_383)
        {
            return 2;
        }

        if (value <= 1_073_741_823)
        {
            return 4;
        }

        return 8;
    }

    private static byte[] SequentialBytes(byte seed, int length)
    {
        byte[] bytes = new byte[length];
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = unchecked((byte)(seed + i));
        }

        return bytes;
    }

    private readonly record struct HandshakePacketCase(
        int PacketNumberLength,
        byte ReservedBits,
        int DestinationConnectionIdLength,
        int SourceConnectionIdLength,
        int ProtectedPayloadLength);

    private readonly record struct HandshakeVersionSpecificFields(
        ulong PayloadLength,
        int PayloadLengthBytes,
        byte[] PacketNumber,
        byte[] ProtectedPayload);
}
