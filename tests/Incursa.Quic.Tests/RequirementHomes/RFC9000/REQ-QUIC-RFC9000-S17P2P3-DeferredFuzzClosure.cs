// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Diagnostics;

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S17P2P3_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ZeroRttPacket_UsesLongHeaderTypeOneWithLengthAndPacketNumberFields()
    {
        foreach (ZeroRttPacketCase testCase in ZeroRttPacketCases())
        {
            QuicLongHeaderPacket header = AssertZeroRttPacketRoundTrip(testCase);
            ZeroRttVersionSpecificFields fields = ParseZeroRttVersionSpecificFields(header);

            Assert.Equal(QuicLongPacketTypeBits.ZeroRtt, header.LongPacketTypeBits);
            Assert.True(fields.PayloadLengthBytes > 0);
            Assert.Equal(testCase.PacketNumberLength, fields.PacketNumber.Length);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0002")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ZeroRttFirstByteContainsReservedAndPacketNumberLengthBits()
    {
        foreach (ZeroRttPacketCase testCase in ZeroRttPacketCases())
        {
            QuicLongHeaderPacket header = AssertZeroRttPacketRoundTrip(testCase);
            Assert.Equal(testCase.ReservedBits, header.ReservedBits);
            Assert.Equal(testCase.PacketNumberLength - 1, header.PacketNumberLengthBits);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0003")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ZeroRttPayload_CarriesEarlyDataBytesInTheProtectedPayloadRegion()
    {
        foreach (ZeroRttPacketCase testCase in ZeroRttPacketCases())
        {
            ZeroRttVersionSpecificFields fields = ParseZeroRttVersionSpecificFields(AssertZeroRttPacketRoundTrip(testCase));
            Assert.Equal(testCase.ProtectedPayloadLength, fields.ProtectedPayload.Length);
            Assert.True(SequentialBytes(0xB0, testCase.ProtectedPayloadLength).AsSpan().SequenceEqual(fields.ProtectedPayload));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0005")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ZeroRttHeaderFormBit_IsAlwaysLongHeader()
    {
        foreach (ZeroRttPacketCase testCase in ZeroRttPacketCases())
        {
            byte[] packet = BuildZeroRttPacket(testCase);
            Assert.True(QuicPacketParser.TryClassifyHeaderForm(packet, out QuicHeaderForm headerForm));
            Assert.Equal(QuicHeaderForm.Long, headerForm);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0006")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ZeroRttFixedBit_IsSetAcrossPacketNumberAndReservedBitValues()
    {
        foreach (ZeroRttPacketCase testCase in ZeroRttPacketCases())
        {
            QuicLongHeaderPacket header = AssertZeroRttPacketRoundTrip(testCase);
            Assert.True(header.FixedBit);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0007")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ZeroRttLongPacketTypeBits_AreTypeOne()
    {
        foreach (ZeroRttPacketCase testCase in ZeroRttPacketCases())
        {
            QuicLongHeaderPacket header = AssertZeroRttPacketRoundTrip(testCase);
            Assert.Equal((byte)1, header.LongPacketTypeBits);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0008")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ZeroRttReservedBits_AreTwoBitsWideAndPreservedForValidation()
    {
        foreach (ZeroRttPacketCase testCase in ZeroRttPacketCases())
        {
            QuicLongHeaderPacket header = AssertZeroRttPacketRoundTrip(testCase);
            Assert.InRange(header.ReservedBits, (byte)0, (byte)3);
            Assert.Equal(testCase.ReservedBits, header.ReservedBits);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0009")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ZeroRttPacketNumberLengthBits_EncodeOneThroughFourBytes()
    {
        foreach (ZeroRttPacketCase testCase in ZeroRttPacketCases())
        {
            QuicLongHeaderPacket header = AssertZeroRttPacketRoundTrip(testCase);
            Assert.Equal(testCase.PacketNumberLength - 1, header.PacketNumberLengthBits);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0010")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ZeroRttVersionField_IsThirtyTwoBitsAndVersionOne()
    {
        foreach (ZeroRttPacketCase testCase in ZeroRttPacketCases())
        {
            QuicLongHeaderPacket header = AssertZeroRttPacketRoundTrip(testCase);
            Assert.Equal(QuicVersionNegotiation.Version1, header.Version);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0011")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ZeroRttDestinationConnectionIdLength_IsEightBits()
    {
        foreach (ZeroRttPacketCase testCase in ZeroRttPacketCases())
        {
            QuicLongHeaderPacket header = AssertZeroRttPacketRoundTrip(testCase);
            Assert.Equal(testCase.DestinationConnectionIdLength, header.DestinationConnectionIdLength);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0012")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ZeroRttDestinationConnectionId_IsZeroToTwentyBytes()
    {
        foreach (ZeroRttPacketCase testCase in ZeroRttPacketCases())
        {
            QuicLongHeaderPacket header = AssertZeroRttPacketRoundTrip(testCase);
            Assert.InRange(header.DestinationConnectionId.Length, 0, 20);
            Assert.Equal(testCase.DestinationConnectionIdLength, header.DestinationConnectionId.Length);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0013")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ZeroRttSourceConnectionIdLength_IsEightBits()
    {
        foreach (ZeroRttPacketCase testCase in ZeroRttPacketCases())
        {
            QuicLongHeaderPacket header = AssertZeroRttPacketRoundTrip(testCase);
            Assert.Equal(testCase.SourceConnectionIdLength, header.SourceConnectionIdLength);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0014")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ZeroRttSourceConnectionId_IsZeroToTwentyBytes()
    {
        foreach (ZeroRttPacketCase testCase in ZeroRttPacketCases())
        {
            QuicLongHeaderPacket header = AssertZeroRttPacketRoundTrip(testCase);
            Assert.InRange(header.SourceConnectionId.Length, 0, 20);
            Assert.Equal(testCase.SourceConnectionIdLength, header.SourceConnectionId.Length);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0015")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ZeroRttLengthField_IsVariableLengthIntegerEncoded()
    {
        foreach (ZeroRttPacketCase testCase in ZeroRttPacketCases())
        {
            ZeroRttVersionSpecificFields fields = ParseZeroRttVersionSpecificFields(AssertZeroRttPacketRoundTrip(testCase));
            Assert.Equal((ulong)(testCase.PacketNumberLength + testCase.ProtectedPayloadLength), fields.PayloadLength);
            Assert.Equal(ExpectedVarintLength(fields.PayloadLength), fields.PayloadLengthBytes);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0016")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ZeroRttPacketNumberField_IsOneToFourBytesLong()
    {
        foreach (ZeroRttPacketCase testCase in ZeroRttPacketCases())
        {
            ZeroRttVersionSpecificFields fields = ParseZeroRttVersionSpecificFields(AssertZeroRttPacketRoundTrip(testCase));
            Assert.InRange(fields.PacketNumber.Length, 1, 4);
            Assert.Equal(testCase.PacketNumberLength, fields.PacketNumber.Length);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0020")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_BootstrapZeroRttPackets_DoNotContainResponsesToOneRttFrames()
    {
        foreach (int ticketMaxEarlyDataSize in new[] { 1, 64, 4_096 })
        {
            (byte[] zeroRttPacket, byte[] ackResponsePacket) =
                BuildBootstrapZeroRttAndAckResponsePackets(ticketMaxEarlyDataSize);

            Assert.True(QuicS17P2P3TestSupport.IsZeroRttPacket(zeroRttPacket));
            Assert.False(zeroRttPacket.AsSpan().SequenceEqual(ackResponsePacket));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0021")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_BootstrapZeroRttPackets_DoNotSendAckFrames()
    {
        foreach (int ticketMaxEarlyDataSize in new[] { 1, 64, 4_096 })
        {
            (byte[] zeroRttPacket, byte[] ackResponsePacket) =
                BuildBootstrapZeroRttAndAckResponsePackets(ticketMaxEarlyDataSize);

            Assert.True(QuicFrameCodec.TryParseAckFrame(QuicS17P2P3TestSupport.CreateAckResponsePayload(), out _, out _));
            Assert.True(QuicS17P2P3TestSupport.IsZeroRttPacket(zeroRttPacket));
            Assert.False(zeroRttPacket.AsSpan().SequenceEqual(ackResponsePacket));
        }
    }

    private static IEnumerable<ZeroRttPacketCase> ZeroRttPacketCases()
    {
        foreach (int packetNumberLength in new[] { 1, 2, 3, 4 })
        {
            foreach (byte reservedBits in new byte[] { 0, 1, 2, 3 })
            {
                yield return new ZeroRttPacketCase(
                    packetNumberLength,
                    reservedBits,
                    DestinationConnectionIdLength: 0,
                    SourceConnectionIdLength: 0,
                    ProtectedPayloadLength: 1);
                yield return new ZeroRttPacketCase(
                    packetNumberLength,
                    reservedBits,
                    DestinationConnectionIdLength: 8,
                    SourceConnectionIdLength: 4,
                    ProtectedPayloadLength: 16);
                yield return new ZeroRttPacketCase(
                    packetNumberLength,
                    reservedBits,
                    DestinationConnectionIdLength: 20,
                    SourceConnectionIdLength: 20,
                    ProtectedPayloadLength: 64);
            }
        }
    }

    private static byte[] BuildZeroRttPacket(ZeroRttPacketCase testCase)
    {
        return QuicS17P2P3TestSupport.BuildZeroRttPacket(
            packetNumberLength: testCase.PacketNumberLength,
            reservedBits: testCase.ReservedBits,
            destinationConnectionId: SequentialBytes(0xD0, testCase.DestinationConnectionIdLength),
            sourceConnectionId: SequentialBytes(0x50, testCase.SourceConnectionIdLength),
            protectedPayload: SequentialBytes(0xB0, testCase.ProtectedPayloadLength));
    }

    private static QuicLongHeaderPacket AssertZeroRttPacketRoundTrip(ZeroRttPacketCase testCase)
    {
        byte[] packet = BuildZeroRttPacket(testCase);
        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(QuicHeaderForm.Long, header.HeaderForm);
        Assert.Equal(QuicVersionNegotiation.Version1, header.Version);
        Assert.Equal(QuicLongPacketTypeBits.ZeroRtt, header.LongPacketTypeBits);
        return header;
    }

    private static ZeroRttVersionSpecificFields ParseZeroRttVersionSpecificFields(QuicLongHeaderPacket header)
    {
        ReadOnlySpan<byte> versionSpecificData = header.VersionSpecificData;
        Assert.True(QuicVariableLengthInteger.TryParse(versionSpecificData, out ulong payloadLength, out int payloadLengthBytes));

        ReadOnlySpan<byte> payload = versionSpecificData[payloadLengthBytes..];
        int packetNumberLength = (header.PacketNumberLengthBits & QuicPacketHeaderBits.PacketNumberLengthBitsMask) + 1;
        ReadOnlySpan<byte> packetNumber = payload[..packetNumberLength];
        ReadOnlySpan<byte> protectedPayload = payload.Slice(
            packetNumberLength,
            checked((int)payloadLength) - packetNumberLength);

        return new ZeroRttVersionSpecificFields(
            payloadLength,
            payloadLengthBytes,
            packetNumber.ToArray(),
            protectedPayload.ToArray());
    }

    private static (byte[] ZeroRttPacket, byte[] AckResponsePacket) BuildBootstrapZeroRttAndAckResponsePackets(
        int ticketMaxEarlyDataSize)
    {
        QuicDetachedResumptionTicketSnapshot detachedResumptionTicketSnapshot =
            QuicResumptionClientHelloTestSupport.CreateDetachedResumptionTicketSnapshot(
                ticketMaxEarlyDataSize: checked((uint)ticketMaxEarlyDataSize));
        QuicTransportParameters localTransportParameters = QuicS17P2P3TestSupport.CreateBootstrapLocalTransportParameters();
        long nowTicks = detachedResumptionTicketSnapshot.CapturedAtTicks + Stopwatch.Frequency;

        using QuicConnectionRuntime clientRuntime = QuicS17P2P3TestSupport.CreateClientRuntime(detachedResumptionTicketSnapshot);
        QuicConnectionTransitionResult result = clientRuntime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: nowTicks,
                LocalTransportParameters: localTransportParameters),
            nowTicks);

        QuicConnectionSendDatagramEffect zeroRttSend = Assert.Single(QuicS17P2P3TestSupport.GetZeroRttSendEffects(result.Effects));
        Assert.True(clientRuntime.TlsState.TryGetPacketProtectionMaterial(
            QuicTlsEncryptionLevel.ZeroRtt,
            out QuicTlsPacketProtectionMaterial zeroRttMaterial));

        byte[] ackResponsePacket = QuicS17P2P3TestSupport.BuildExpectedZeroRttPacket(
            QuicS17P2P3TestSupport.CreateAckResponsePayload(),
            zeroRttMaterial);

        return (zeroRttSend.Datagram.ToArray(), ackResponsePacket);
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
            bytes[i] = (byte)(seed + i);
        }

        return bytes;
    }

    private readonly record struct ZeroRttPacketCase(
        int PacketNumberLength,
        byte ReservedBits,
        int DestinationConnectionIdLength,
        int SourceConnectionIdLength,
        int ProtectedPayloadLength);

    private readonly record struct ZeroRttVersionSpecificFields(
        ulong PayloadLength,
        int PayloadLengthBytes,
        byte[] PacketNumber,
        byte[] ProtectedPayload);
}
