// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers.Binary;

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S17P2P1_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_VersionNegotiationResponse_IsProducedOnlyForUnsupportedClientVersions()
    {
        foreach (VersionNegotiationFormatCase testCase in VersionNegotiationFormatCases())
        {
            Assert.True(QuicVersionNegotiation.ShouldSendVersionNegotiation(
                testCase.ClientSelectedVersion,
                testCase.ServerSupportedVersions));

            QuicVersionNegotiationPacket packet = AssertFormattedVersionNegotiationRoundTrip(testCase);
            Assert.False(packet.ContainsSupportedVersion(testCase.ClientSelectedVersion));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0003")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_VersionNegotiationHeaderFormBit_IsAlwaysLongHeader()
    {
        foreach (VersionNegotiationParseCase testCase in VersionNegotiationParseCases())
        {
            byte[] packetBytes = BuildVersionNegotiationPacket(testCase);
            Assert.True(QuicPacketParser.TryClassifyHeaderForm(packetBytes, out QuicHeaderForm headerForm));
            Assert.Equal(QuicHeaderForm.Long, headerForm);

            QuicVersionNegotiationPacket packet = AssertParsedVersionNegotiationRoundTrip(testCase);
            Assert.Equal(QuicHeaderForm.Long, packet.HeaderForm);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0004")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_VersionNegotiationUnusedField_IsSevenBitsAndPreserved()
    {
        foreach (VersionNegotiationParseCase testCase in VersionNegotiationParseCases())
        {
            QuicVersionNegotiationPacket packet = AssertParsedVersionNegotiationRoundTrip(testCase);
            Assert.InRange(packet.HeaderControlBits, (byte)0, (byte)0x7F);
            Assert.Equal((byte)(testCase.HeaderControlBits & 0x7F), packet.HeaderControlBits);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0005")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_VersionNegotiationVersionField_IsThirtyTwoZeroBits()
    {
        foreach (VersionNegotiationParseCase testCase in VersionNegotiationParseCases())
        {
            byte[] packetBytes = BuildVersionNegotiationPacket(testCase);
            QuicVersionNegotiationPacket packet = AssertParsedVersionNegotiationRoundTrip(testCase);

            Assert.Equal((uint)0, packet.Version);
            Assert.Equal((uint)0, BinaryPrimitives.ReadUInt32BigEndian(packetBytes.AsSpan(1, sizeof(uint))));
            Assert.True(packet.IsVersionNegotiation);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0006")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_VersionNegotiationDestinationConnectionIdLength_IsEightBits()
    {
        foreach (VersionNegotiationParseCase testCase in VersionNegotiationParseCases())
        {
            QuicVersionNegotiationPacket packet = AssertParsedVersionNegotiationRoundTrip(testCase);
            Assert.Equal(testCase.DestinationConnectionIdLength, packet.DestinationConnectionIdLength);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0007")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_VersionNegotiationDestinationConnectionId_IsZeroToTwoHundredFiftyFiveBytes()
    {
        foreach (VersionNegotiationParseCase testCase in VersionNegotiationParseCases())
        {
            QuicVersionNegotiationPacket packet = AssertParsedVersionNegotiationRoundTrip(testCase);
            Assert.InRange(packet.DestinationConnectionId.Length, 0, byte.MaxValue);
            Assert.Equal(testCase.DestinationConnectionIdLength, packet.DestinationConnectionId.Length);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0008")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_VersionNegotiationSourceConnectionIdLength_IsEightBits()
    {
        foreach (VersionNegotiationParseCase testCase in VersionNegotiationParseCases())
        {
            QuicVersionNegotiationPacket packet = AssertParsedVersionNegotiationRoundTrip(testCase);
            Assert.Equal(testCase.SourceConnectionIdLength, packet.SourceConnectionIdLength);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0009")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_VersionNegotiationSourceConnectionId_IsZeroToTwoHundredFiftyFiveBytes()
    {
        foreach (VersionNegotiationParseCase testCase in VersionNegotiationParseCases())
        {
            QuicVersionNegotiationPacket packet = AssertParsedVersionNegotiationRoundTrip(testCase);
            Assert.InRange(packet.SourceConnectionId.Length, 0, byte.MaxValue);
            Assert.Equal(testCase.SourceConnectionIdLength, packet.SourceConnectionId.Length);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0010")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_VersionNegotiationFormatter_SetsServerChosenUnusedFieldValue()
    {
        foreach (VersionNegotiationFormatCase testCase in VersionNegotiationFormatCases())
        {
            byte[] packetBytes = AssertFormattedVersionNegotiationBytes(testCase);
            QuicVersionNegotiationPacket packet = AssertFormattedVersionNegotiationRoundTrip(testCase);

            Assert.Equal((byte)0xC0, packetBytes[0]);
            Assert.Equal((byte)0x40, packet.HeaderControlBits);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0012")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_VersionNegotiationFormatter_SetsMostSignificantUnusedBit()
    {
        foreach (VersionNegotiationFormatCase testCase in VersionNegotiationFormatCases())
        {
            byte[] packetBytes = AssertFormattedVersionNegotiationBytes(testCase);
            Assert.NotEqual(0, packetBytes[0] & 0x40);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0015")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_VersionNegotiationFormatter_CopiesClientDestinationConnectionIdIntoSourceField()
    {
        foreach (VersionNegotiationFormatCase testCase in VersionNegotiationFormatCases())
        {
            QuicVersionNegotiationPacket packet = AssertFormattedVersionNegotiationRoundTrip(testCase);
            byte[] expectedSourceConnectionId = SequentialBytes(0xD0, testCase.ClientDestinationConnectionIdLength);

            Assert.True(expectedSourceConnectionId.AsSpan().SequenceEqual(packet.SourceConnectionId));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0018")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_VersionNegotiationDecision_RequiresUnsupportedClientVersion()
    {
        foreach (VersionNegotiationFormatCase testCase in VersionNegotiationFormatCases())
        {
            Assert.True(QuicVersionNegotiation.ShouldSendVersionNegotiation(
                testCase.ClientSelectedVersion,
                testCase.ServerSupportedVersions));

            Assert.False(QuicVersionNegotiation.ShouldSendVersionNegotiation(
                testCase.ServerSupportedVersions[0],
                testCase.ServerSupportedVersions));
            Assert.False(QuicVersionNegotiation.ShouldSendVersionNegotiation(
                QuicVersionNegotiation.VersionNegotiationVersion,
                testCase.ServerSupportedVersions));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0019")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_VersionNegotiationPacket_ContainsSupportedVersionsWithoutLengthOrPacketNumberFields()
    {
        foreach (VersionNegotiationParseCase testCase in VersionNegotiationParseCases())
        {
            byte[] packetBytes = BuildVersionNegotiationPacket(testCase);
            QuicVersionNegotiationPacket packet = AssertParsedVersionNegotiationRoundTrip(testCase);

            int supportedVersionOffset = QuicHeaderTestData.GetLongHeaderPayloadOffset(packetBytes);
            Assert.Equal(supportedVersionOffset, packetBytes.Length - packet.SupportedVersionBytes.Length);
            Assert.Equal(testCase.SupportedVersions.Length * sizeof(uint), packet.SupportedVersionBytes.Length);
            Assert.True(packetBytes.AsSpan(supportedVersionOffset).SequenceEqual(packet.SupportedVersionBytes));
        }
    }

    private static IEnumerable<VersionNegotiationParseCase> VersionNegotiationParseCases()
    {
        foreach (byte headerControlBits in new byte[] { 0x00, 0x01, 0x40, 0x6E, 0x7F })
        {
            yield return new VersionNegotiationParseCase(
                headerControlBits,
                DestinationConnectionIdLength: 0,
                SourceConnectionIdLength: 0,
                [QuicVersionNegotiation.Version1]);
            yield return new VersionNegotiationParseCase(
                headerControlBits,
                DestinationConnectionIdLength: 1,
                SourceConnectionIdLength: 2,
                [QuicVersionNegotiation.Version1, 0x11223344]);
            yield return new VersionNegotiationParseCase(
                headerControlBits,
                DestinationConnectionIdLength: 20,
                SourceConnectionIdLength: 21,
                [0x11223344, 0xAABBCCDD, QuicVersionNegotiation.CreateReservedVersion(0x12345678)]);
            yield return new VersionNegotiationParseCase(
                headerControlBits,
                DestinationConnectionIdLength: byte.MaxValue,
                SourceConnectionIdLength: byte.MaxValue,
                [0x11223344]);
        }
    }

    private static IEnumerable<VersionNegotiationFormatCase> VersionNegotiationFormatCases()
    {
        yield return new VersionNegotiationFormatCase(
            ClientSelectedVersion: 0x11223344,
            ClientDestinationConnectionIdLength: 0,
            ClientSourceConnectionIdLength: 0,
            [QuicVersionNegotiation.Version1]);
        yield return new VersionNegotiationFormatCase(
            ClientSelectedVersion: 0xAABBCCDD,
            ClientDestinationConnectionIdLength: 8,
            ClientSourceConnectionIdLength: 4,
            [QuicVersionNegotiation.Version1, QuicVersionNegotiation.CreateReservedVersion(0x12345678)]);
        yield return new VersionNegotiationFormatCase(
            ClientSelectedVersion: 0xFEEDCAFE,
            ClientDestinationConnectionIdLength: byte.MaxValue,
            ClientSourceConnectionIdLength: byte.MaxValue,
            [QuicVersionNegotiation.Version1, QuicVersionNegotiation.Version2]);
    }

    private static byte[] BuildVersionNegotiationPacket(VersionNegotiationParseCase testCase)
    {
        return QuicHeaderTestData.BuildVersionNegotiation(
            testCase.HeaderControlBits,
            SequentialBytes(0xD0, testCase.DestinationConnectionIdLength),
            SequentialBytes(0x50, testCase.SourceConnectionIdLength),
            testCase.SupportedVersions);
    }

    private static QuicVersionNegotiationPacket AssertParsedVersionNegotiationRoundTrip(VersionNegotiationParseCase testCase)
    {
        byte[] packetBytes = BuildVersionNegotiationPacket(testCase);
        Assert.True(QuicPacketParser.TryParseVersionNegotiation(packetBytes, out QuicVersionNegotiationPacket packet));

        Assert.Equal((byte)(testCase.HeaderControlBits & 0x7F), packet.HeaderControlBits);
        Assert.Equal((uint)0, packet.Version);
        Assert.Equal(testCase.DestinationConnectionIdLength, packet.DestinationConnectionIdLength);
        Assert.Equal(testCase.SourceConnectionIdLength, packet.SourceConnectionIdLength);
        Assert.Equal(testCase.SupportedVersions.Length, packet.SupportedVersionCount);

        for (int index = 0; index < testCase.SupportedVersions.Length; index++)
        {
            Assert.Equal(testCase.SupportedVersions[index], packet.GetSupportedVersion(index));
            Assert.True(packet.ContainsSupportedVersion(testCase.SupportedVersions[index]));
        }

        return packet;
    }

    private static byte[] AssertFormattedVersionNegotiationBytes(VersionNegotiationFormatCase testCase)
    {
        byte[] destination = new byte[
            1
            + sizeof(uint)
            + 1
            + testCase.ClientSourceConnectionIdLength
            + 1
            + testCase.ClientDestinationConnectionIdLength
            + (testCase.ServerSupportedVersions.Length * sizeof(uint))];

        Assert.True(QuicVersionNegotiation.TryFormatVersionNegotiationResponse(
            testCase.ClientSelectedVersion,
            SequentialBytes(0xD0, testCase.ClientDestinationConnectionIdLength),
            SequentialBytes(0x50, testCase.ClientSourceConnectionIdLength),
            testCase.ServerSupportedVersions,
            destination,
            out int bytesWritten));
        Assert.Equal(destination.Length, bytesWritten);
        return destination;
    }

    private static QuicVersionNegotiationPacket AssertFormattedVersionNegotiationRoundTrip(VersionNegotiationFormatCase testCase)
    {
        byte[] packetBytes = AssertFormattedVersionNegotiationBytes(testCase);
        Assert.True(QuicPacketParser.TryParseVersionNegotiation(packetBytes, out QuicVersionNegotiationPacket packet));

        byte[] expectedDestinationConnectionId = SequentialBytes(0x50, testCase.ClientSourceConnectionIdLength);
        byte[] expectedSourceConnectionId = SequentialBytes(0xD0, testCase.ClientDestinationConnectionIdLength);
        Assert.True(expectedDestinationConnectionId.AsSpan().SequenceEqual(packet.DestinationConnectionId));
        Assert.True(expectedSourceConnectionId.AsSpan().SequenceEqual(packet.SourceConnectionId));
        Assert.Equal(testCase.ServerSupportedVersions.Length, packet.SupportedVersionCount);

        for (int index = 0; index < testCase.ServerSupportedVersions.Length; index++)
        {
            Assert.Equal(testCase.ServerSupportedVersions[index], packet.GetSupportedVersion(index));
        }

        return packet;
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

    private readonly record struct VersionNegotiationParseCase(
        byte HeaderControlBits,
        int DestinationConnectionIdLength,
        int SourceConnectionIdLength,
        uint[] SupportedVersions);

    private readonly record struct VersionNegotiationFormatCase(
        uint ClientSelectedVersion,
        int ClientDestinationConnectionIdLength,
        int ClientSourceConnectionIdLength,
        uint[] ServerSupportedVersions);
}
