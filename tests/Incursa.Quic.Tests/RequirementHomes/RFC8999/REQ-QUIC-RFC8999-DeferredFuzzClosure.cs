// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers.Binary;

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC8999_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_LongHeaderFormBit_ClassifiesLongHeaderBoundaryInputs()
    {
        foreach (LongHeaderCase testCase in LongHeaderCases())
        {
            AssertLongHeaderInvariantFieldsRoundTrip(testCase);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0002")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_LongHeaderVersionSpecificBits_ArePreservedAcrossControlBitValues()
    {
        foreach (byte headerControlBits in new byte[] { 0x40, 0x41, 0x52, 0x63, 0x7F })
        {
            QuicLongHeaderPacket header = AssertLongHeaderInvariantFieldsRoundTrip(new LongHeaderCase(
                headerControlBits,
                0x11223344,
                DestinationConnectionIdLength: 3,
                SourceConnectionIdLength: 4,
                VersionSpecificDataLength: 5));

            Assert.Equal((byte)(headerControlBits & 0x7F), header.HeaderControlBits);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0003")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_LongHeaderVersionField_RoundTripsAcrossVersionValues()
    {
        foreach (uint version in new uint[] { 0, 0x11223344, 0xA1A2A3A4, 0xFEEDCAFE })
        {
            QuicLongHeaderPacket header = AssertLongHeaderInvariantFieldsRoundTrip(new LongHeaderCase(
                0x40,
                version,
                DestinationConnectionIdLength: 2,
                SourceConnectionIdLength: 3,
                VersionSpecificDataLength: 5));

            Assert.Equal(version, header.Version);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0004")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_DestinationConnectionIdLengthByte_RoundTripsAcrossBoundaryLengths()
    {
        foreach (int destinationConnectionIdLength in new[] { 0, 1, 20, 21, byte.MaxValue })
        {
            QuicLongHeaderPacket header = AssertLongHeaderInvariantFieldsRoundTrip(new LongHeaderCase(
                0x41,
                0x11223344,
                destinationConnectionIdLength,
                SourceConnectionIdLength: 3,
                VersionSpecificDataLength: 5));

            Assert.Equal(destinationConnectionIdLength, header.DestinationConnectionIdLength);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0005")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_DestinationConnectionIdField_FollowsLengthByteAcrossBoundaryLengths()
    {
        foreach (int destinationConnectionIdLength in new[] { 0, 1, 20, 21, byte.MaxValue })
        {
            QuicLongHeaderPacket header = AssertLongHeaderInvariantFieldsRoundTrip(new LongHeaderCase(
                0x52,
                0x11223344,
                destinationConnectionIdLength,
                SourceConnectionIdLength: 4,
                VersionSpecificDataLength: 6));

            Assert.Equal(destinationConnectionIdLength, header.DestinationConnectionId.Length);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0006")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_SourceConnectionIdLengthByte_RoundTripsAcrossBoundaryLengths()
    {
        foreach (int sourceConnectionIdLength in new[] { 0, 1, 20, 21, byte.MaxValue })
        {
            QuicLongHeaderPacket header = AssertLongHeaderInvariantFieldsRoundTrip(new LongHeaderCase(
                0x63,
                0x11223344,
                DestinationConnectionIdLength: 4,
                sourceConnectionIdLength,
                VersionSpecificDataLength: 6));

            Assert.Equal(sourceConnectionIdLength, header.SourceConnectionIdLength);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0007")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_SourceConnectionIdField_FollowsLengthByteAcrossBoundaryLengths()
    {
        foreach (int sourceConnectionIdLength in new[] { 0, 1, 20, 21, byte.MaxValue })
        {
            QuicLongHeaderPacket header = AssertLongHeaderInvariantFieldsRoundTrip(new LongHeaderCase(
                0x7F,
                0x11223344,
                DestinationConnectionIdLength: 5,
                sourceConnectionIdLength,
                VersionSpecificDataLength: 7));

            Assert.Equal(sourceConnectionIdLength, header.SourceConnectionId.Length);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0008")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_VersionSpecificRemainder_IsPreservedAcrossPayloadLengths()
    {
        foreach (int versionSpecificDataLength in new[] { 0, 1, 3, 17, 31 })
        {
            QuicLongHeaderPacket header = AssertLongHeaderInvariantFieldsRoundTrip(new LongHeaderCase(
                0x52,
                0x11223344,
                DestinationConnectionIdLength: 7,
                SourceConnectionIdLength: 8,
                versionSpecificDataLength));

            Assert.Equal(versionSpecificDataLength, header.VersionSpecificData.Length);
        }
    }

    private static IEnumerable<LongHeaderCase> LongHeaderCases()
    {
        foreach (byte headerControlBits in new byte[] { 0x40, 0x41, 0x52, 0x63, 0x7F })
        {
            yield return new LongHeaderCase(
                headerControlBits,
                0x0A0B0C0D,
                DestinationConnectionIdLength: 0,
                SourceConnectionIdLength: 0,
                VersionSpecificDataLength: 0);
            yield return new LongHeaderCase(
                headerControlBits,
                0x11223344,
                DestinationConnectionIdLength: 1,
                SourceConnectionIdLength: 2,
                VersionSpecificDataLength: 3);
            yield return new LongHeaderCase(
                headerControlBits,
                0xA1A2A3A4,
                DestinationConnectionIdLength: 20,
                SourceConnectionIdLength: 21,
                VersionSpecificDataLength: 17);
            yield return new LongHeaderCase(
                headerControlBits,
                0xFEEDCAFE,
                DestinationConnectionIdLength: byte.MaxValue,
                SourceConnectionIdLength: byte.MaxValue,
                VersionSpecificDataLength: 31);
        }
    }

    private static QuicLongHeaderPacket AssertLongHeaderInvariantFieldsRoundTrip(LongHeaderCase testCase)
    {
        byte[] destinationConnectionId = SequentialBytes(0xD0, testCase.DestinationConnectionIdLength);
        byte[] sourceConnectionId = SequentialBytes(0x50, testCase.SourceConnectionIdLength);
        byte[] versionSpecificData = SequentialBytes(0x90, testCase.VersionSpecificDataLength);
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            testCase.HeaderControlBits,
            testCase.Version,
            destinationConnectionId,
            sourceConnectionId,
            versionSpecificData);

        Assert.True(QuicPacketParser.TryClassifyHeaderForm(packet, out QuicHeaderForm headerForm));
        Assert.Equal(QuicHeaderForm.Long, headerForm);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((byte)(testCase.HeaderControlBits & 0x7F), header.HeaderControlBits);
        Assert.Equal(testCase.Version, header.Version);
        Assert.Equal(testCase.DestinationConnectionIdLength, header.DestinationConnectionIdLength);
        Assert.Equal(testCase.SourceConnectionIdLength, header.SourceConnectionIdLength);
        Assert.True(destinationConnectionId.AsSpan().SequenceEqual(header.DestinationConnectionId));
        Assert.True(sourceConnectionId.AsSpan().SequenceEqual(header.SourceConnectionId));
        Assert.True(versionSpecificData.AsSpan().SequenceEqual(header.VersionSpecificData));

        Assert.Equal(testCase.Version, BinaryPrimitives.ReadUInt32BigEndian(packet.AsSpan(1, sizeof(uint))));
        Assert.Equal(testCase.DestinationConnectionIdLength, packet[5]);
        int sourceConnectionIdLengthOffset = 6 + testCase.DestinationConnectionIdLength;
        Assert.Equal(testCase.SourceConnectionIdLength, packet[sourceConnectionIdLengthOffset]);
        Assert.Equal(
            sourceConnectionIdLengthOffset + 1 + testCase.SourceConnectionIdLength,
            QuicHeaderTestData.GetLongHeaderPayloadOffset(packet));

        return header;
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

    private readonly record struct LongHeaderCase(
        byte HeaderControlBits,
        uint Version,
        int DestinationConnectionIdLength,
        int SourceConnectionIdLength,
        int VersionSpecificDataLength);
}
