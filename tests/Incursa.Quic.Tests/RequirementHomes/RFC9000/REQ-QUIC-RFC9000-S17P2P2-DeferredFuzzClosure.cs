// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S17P2P2_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_InitialPacketType_UsesLongHeaderTypeZero()
    {
        foreach (InitialPacketCase testCase in InitialPacketCases())
        {
            QuicLongHeaderPacket header = AssertInitialPacketRoundTrip(testCase);
            Assert.Equal(QuicLongPacketTypeBits.Initial, header.LongPacketTypeBits);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0002")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_InitialHeaderFormBit_IsAlwaysLongHeader()
    {
        foreach (InitialPacketCase testCase in InitialPacketCases())
        {
            byte[] packet = BuildInitialPacket(testCase);
            Assert.True(QuicPacketParser.TryClassifyHeaderForm(packet, out QuicHeaderForm headerForm));
            Assert.Equal(QuicHeaderForm.Long, headerForm);
            Assert.True((packet[0] & QuicPacketHeaderBits.HeaderFormBitMask) != 0);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0003")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_InitialFixedBit_IsSetAcrossPacketNumberAndReservedBitValues()
    {
        foreach (InitialPacketCase testCase in InitialPacketCases())
        {
            QuicLongHeaderPacket header = AssertInitialPacketRoundTrip(testCase);
            Assert.True(header.FixedBit);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0004")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_InitialLongPacketTypeBits_AreTypeZero()
    {
        foreach (InitialPacketCase testCase in InitialPacketCases())
        {
            QuicLongHeaderPacket header = AssertInitialPacketRoundTrip(testCase);
            Assert.Equal((byte)0, header.LongPacketTypeBits);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0005")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_InitialReservedBits_AreTwoBitsWideAndPreservedForValidation()
    {
        foreach (InitialPacketCase testCase in InitialPacketCases())
        {
            QuicLongHeaderPacket header = AssertInitialPacketRoundTrip(testCase);
            Assert.InRange(header.ReservedBits, (byte)0, (byte)3);
            Assert.Equal(testCase.ReservedBits, header.ReservedBits);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0006")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_InitialPacketNumberLengthBits_EncodeOneThroughFourBytes()
    {
        foreach (InitialPacketCase testCase in InitialPacketCases())
        {
            QuicLongHeaderPacket header = AssertInitialPacketRoundTrip(testCase);
            Assert.Equal(testCase.PacketNumberLength - 1, header.PacketNumberLengthBits);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0007")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_InitialVersionField_IsThirtyTwoBitsAndVersionOne()
    {
        foreach (InitialPacketCase testCase in InitialPacketCases())
        {
            QuicLongHeaderPacket header = AssertInitialPacketRoundTrip(testCase);
            Assert.Equal(QuicVersionNegotiation.Version1, header.Version);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0008")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_InitialDestinationConnectionIdLength_IsEightBits()
    {
        foreach (InitialPacketCase testCase in InitialPacketCases())
        {
            QuicLongHeaderPacket header = AssertInitialPacketRoundTrip(testCase);
            Assert.Equal(testCase.DestinationConnectionIdLength, header.DestinationConnectionIdLength);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0009")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_InitialDestinationConnectionId_IsZeroToTwentyBytes()
    {
        foreach (InitialPacketCase testCase in InitialPacketCases())
        {
            QuicLongHeaderPacket header = AssertInitialPacketRoundTrip(testCase);
            Assert.InRange(header.DestinationConnectionId.Length, 0, 20);
            Assert.Equal(testCase.DestinationConnectionIdLength, header.DestinationConnectionId.Length);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0010")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_InitialSourceConnectionIdLength_IsEightBits()
    {
        foreach (InitialPacketCase testCase in InitialPacketCases())
        {
            QuicLongHeaderPacket header = AssertInitialPacketRoundTrip(testCase);
            Assert.Equal(testCase.SourceConnectionIdLength, header.SourceConnectionIdLength);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0011")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_InitialSourceConnectionId_IsZeroToTwentyBytes()
    {
        foreach (InitialPacketCase testCase in InitialPacketCases())
        {
            QuicLongHeaderPacket header = AssertInitialPacketRoundTrip(testCase);
            Assert.InRange(header.SourceConnectionId.Length, 0, 20);
            Assert.Equal(testCase.SourceConnectionIdLength, header.SourceConnectionId.Length);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0012")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_InitialTokenLength_IsVariableLengthIntegerEncoded()
    {
        foreach (InitialPacketCase testCase in InitialPacketCases())
        {
            InitialVersionSpecificFields fields = ParseInitialVersionSpecificFields(AssertInitialPacketRoundTrip(testCase));
            Assert.Equal(testCase.TokenLength, (int)fields.TokenLength);
            Assert.Equal(ExpectedVarintLength((ulong)testCase.TokenLength), fields.TokenLengthBytes);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0013")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_InitialLengthField_IsVariableLengthIntegerEncoded()
    {
        foreach (InitialPacketCase testCase in InitialPacketCases())
        {
            InitialVersionSpecificFields fields = ParseInitialVersionSpecificFields(AssertInitialPacketRoundTrip(testCase));
            Assert.Equal((ulong)(testCase.PacketNumberLength + testCase.ProtectedPayloadLength), fields.PayloadLength);
            Assert.Equal(ExpectedVarintLength(fields.PayloadLength), fields.PayloadLengthBytes);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0014")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_InitialPacketNumberField_IsOneToFourBytesLong()
    {
        foreach (InitialPacketCase testCase in InitialPacketCases())
        {
            InitialVersionSpecificFields fields = ParseInitialVersionSpecificFields(AssertInitialPacketRoundTrip(testCase));
            Assert.InRange(fields.PacketNumber.Length, 1, 4);
            Assert.Equal(testCase.PacketNumberLength, fields.PacketNumber.Length);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0015")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_InitialPacketContainsLongHeaderLengthAndPacketNumberFields()
    {
        foreach (InitialPacketCase testCase in InitialPacketCases())
        {
            QuicLongHeaderPacket header = AssertInitialPacketRoundTrip(testCase);
            InitialVersionSpecificFields fields = ParseInitialVersionSpecificFields(header);
            Assert.Equal(QuicHeaderForm.Long, header.HeaderForm);
            Assert.True(fields.PayloadLengthBytes > 0);
            Assert.Equal(testCase.PacketNumberLength, fields.PacketNumber.Length);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0016")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_InitialFirstByteContainsReservedAndPacketNumberLengthBits()
    {
        foreach (InitialPacketCase testCase in InitialPacketCases())
        {
            QuicLongHeaderPacket header = AssertInitialPacketRoundTrip(testCase);
            Assert.Equal(testCase.ReservedBits, header.ReservedBits);
            Assert.Equal(testCase.PacketNumberLength - 1, header.PacketNumberLengthBits);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0017")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_InitialTokenLengthSpecifiesTokenFieldLengthInBytes()
    {
        foreach (InitialPacketCase testCase in InitialPacketCases())
        {
            InitialVersionSpecificFields fields = ParseInitialVersionSpecificFields(AssertInitialPacketRoundTrip(testCase));
            Assert.Equal(testCase.TokenLength, fields.Token.Length);
            Assert.Equal(fields.TokenLength, (ulong)fields.Token.Length);
        }
    }

    private static IEnumerable<InitialPacketCase> InitialPacketCases()
    {
        foreach (int packetNumberLength in new[] { 1, 2, 3, 4 })
        {
            foreach (byte reservedBits in new byte[] { 0, 1, 2, 3 })
            {
                yield return new InitialPacketCase(
                    packetNumberLength,
                    reservedBits,
                    DestinationConnectionIdLength: 0,
                    SourceConnectionIdLength: 0,
                    TokenLength: 0,
                    ProtectedPayloadLength: 1);
                yield return new InitialPacketCase(
                    packetNumberLength,
                    reservedBits,
                    DestinationConnectionIdLength: 8,
                    SourceConnectionIdLength: 4,
                    TokenLength: 1,
                    ProtectedPayloadLength: 16);
                yield return new InitialPacketCase(
                    packetNumberLength,
                    reservedBits,
                    DestinationConnectionIdLength: 20,
                    SourceConnectionIdLength: 20,
                    TokenLength: 63,
                    ProtectedPayloadLength: 64);
            }
        }
    }

    private static byte[] BuildInitialPacket(InitialPacketCase testCase)
    {
        return QuicS17P2P2TestSupport.BuildInitialPacket(
            packetNumberLength: testCase.PacketNumberLength,
            reservedBits: testCase.ReservedBits,
            destinationConnectionId: QuicS17P2P2TestSupport.CreateSequentialBytes(0xD0, testCase.DestinationConnectionIdLength),
            sourceConnectionId: QuicS17P2P2TestSupport.CreateSequentialBytes(0x50, testCase.SourceConnectionIdLength),
            token: QuicS17P2P2TestSupport.CreateSequentialBytes(0xA0, testCase.TokenLength),
            protectedPayload: QuicS17P2P2TestSupport.CreateSequentialBytes(0xB0, testCase.ProtectedPayloadLength));
    }

    private static QuicLongHeaderPacket AssertInitialPacketRoundTrip(InitialPacketCase testCase)
    {
        byte[] packet = BuildInitialPacket(testCase);
        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(QuicHeaderForm.Long, header.HeaderForm);
        Assert.Equal(QuicVersionNegotiation.Version1, header.Version);
        Assert.Equal(QuicLongPacketTypeBits.Initial, header.LongPacketTypeBits);
        return header;
    }

    private static InitialVersionSpecificFields ParseInitialVersionSpecificFields(QuicLongHeaderPacket header)
    {
        ReadOnlySpan<byte> versionSpecificData = header.VersionSpecificData;
        Assert.True(QuicVariableLengthInteger.TryParse(
            versionSpecificData,
            out ulong tokenLength,
            out int tokenLengthBytes));

        ReadOnlySpan<byte> afterTokenLength = versionSpecificData[tokenLengthBytes..];
        ReadOnlySpan<byte> token = afterTokenLength[..checked((int)tokenLength)];
        ReadOnlySpan<byte> afterToken = afterTokenLength[checked((int)tokenLength)..];
        Assert.True(QuicVariableLengthInteger.TryParse(afterToken, out ulong payloadLength, out int payloadLengthBytes));

        ReadOnlySpan<byte> payload = afterToken[payloadLengthBytes..];
        int packetNumberLength = (header.PacketNumberLengthBits & QuicPacketHeaderBits.PacketNumberLengthBitsMask) + 1;
        ReadOnlySpan<byte> packetNumber = payload[..packetNumberLength];
        ReadOnlySpan<byte> protectedPayload = payload[packetNumberLength..checked((int)payloadLength)];

        return new InitialVersionSpecificFields(
            tokenLength,
            tokenLengthBytes,
            token.ToArray(),
            payloadLength,
            payloadLengthBytes,
            packetNumber.ToArray(),
            protectedPayload.ToArray());
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

    private readonly record struct InitialPacketCase(
        int PacketNumberLength,
        byte ReservedBits,
        int DestinationConnectionIdLength,
        int SourceConnectionIdLength,
        int TokenLength,
        int ProtectedPayloadLength);

    private readonly record struct InitialVersionSpecificFields(
        ulong TokenLength,
        int TokenLengthBytes,
        byte[] Token,
        ulong PayloadLength,
        int PayloadLengthBytes,
        byte[] PacketNumber,
        byte[] ProtectedPayload);
}
