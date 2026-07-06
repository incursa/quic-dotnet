// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S17P2_NewIdDeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0914")]
    [Requirement("REQ-QUIC-RFC9000-0915")]
    [Requirement("REQ-QUIC-RFC9000-0916")]
    [Requirement("REQ-QUIC-RFC9000-0939")]
    [Requirement("REQ-QUIC-RFC9000-0944")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_LongHeaderFixedWidthFieldsAndConnectionIdLengthBytesArePreserved()
    {
        foreach (LongHeaderFixedFieldCase testCase in LongHeaderFixedFieldCases())
        {
            byte[] packet = QuicInitialPacketProtectionTestData.BuildInitialPlaintextPacket(
                testCase.DestinationConnectionId,
                testCase.SourceConnectionId,
                token: [],
                testCase.PacketNumber,
                plaintextPayload: [0x41, 0x42, 0x43]);

            Assert.True(QuicPacketParsing.TryParseLongHeaderFields(
                packet,
                out byte headerControlBits,
                out uint version,
                out ReadOnlySpan<byte> parsedDestinationConnectionId,
                out ReadOnlySpan<byte> parsedSourceConnectionId,
                out ReadOnlySpan<byte> versionSpecificData));

            Assert.Equal(QuicVersionNegotiation.Version1, version);
            Assert.True(new byte[] { 0x00, 0x00, 0x00, 0x01 }.AsSpan().SequenceEqual(packet.AsSpan(1, 4)));
            Assert.Equal(testCase.DestinationConnectionId.Length, packet[5]);
            Assert.Equal(testCase.SourceConnectionId.Length, packet[6 + testCase.DestinationConnectionId.Length]);
            Assert.True(testCase.DestinationConnectionId.AsSpan().SequenceEqual(parsedDestinationConnectionId));
            Assert.True(testCase.SourceConnectionId.AsSpan().SequenceEqual(parsedSourceConnectionId));
            Assert.Equal((byte)(testCase.PacketNumber.Length - 1), (byte)(headerControlBits & QuicPacketHeaderBits.PacketNumberLengthBitsMask));
            Assert.True(testCase.PacketNumber.AsSpan().SequenceEqual(GetInitialPacketNumberBytes(versionSpecificData, testCase.PacketNumber.Length)));
        }
    }

    private static IEnumerable<LongHeaderFixedFieldCase> LongHeaderFixedFieldCases()
    {
        yield return new LongHeaderFixedFieldCase([], [], [0x01]);
        yield return new LongHeaderFixedFieldCase([0xD0], [0x50], [0x01, 0x02]);
        yield return new LongHeaderFixedFieldCase(SequentialBytes(0xD0, 8), SequentialBytes(0x50, 8), [0x01, 0x02, 0x03]);
        yield return new LongHeaderFixedFieldCase(SequentialBytes(0xD0, 20), SequentialBytes(0x50, 20), [0x01, 0x02, 0x03, 0x04]);

        Random random = new(0x1702);
        for (int i = 0; i < 64; i++)
        {
            int destinationConnectionIdLength = random.Next(0, 21);
            int sourceConnectionIdLength = random.Next(0, 21);
            int packetNumberLength = random.Next(1, 5);

            yield return new LongHeaderFixedFieldCase(
                QuicHeaderTestData.RandomBytes(random, destinationConnectionIdLength),
                QuicHeaderTestData.RandomBytes(random, sourceConnectionIdLength),
                QuicHeaderTestData.RandomBytes(random, packetNumberLength));
        }
    }

    private static byte[] SequentialBytes(byte first, int length)
    {
        byte[] bytes = new byte[length];
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = (byte)(first + i);
        }

        return bytes;
    }

    private static ReadOnlySpan<byte> GetInitialPacketNumberBytes(ReadOnlySpan<byte> versionSpecificData, int packetNumberLength)
    {
        Assert.True(QuicVariableLengthInteger.TryParse(versionSpecificData, out ulong tokenLength, out int tokenLengthBytes));

        ReadOnlySpan<byte> afterToken = versionSpecificData.Slice(tokenLengthBytes + checked((int)tokenLength));
        Assert.True(QuicVariableLengthInteger.TryParse(afterToken, out _, out int lengthFieldBytes));

        return afterToken.Slice(lengthFieldBytes, packetNumberLength);
    }

    private sealed record LongHeaderFixedFieldCase(
        byte[] DestinationConnectionId,
        byte[] SourceConnectionId,
        byte[] PacketNumber);
}
