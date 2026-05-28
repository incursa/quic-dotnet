// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class QuicHeaderParsingUnitTests
{
    [Fact]
    public void TryClassifyHeaderForm_RecognizesLongAndShortPackets()
    {
        byte[] shortPacket = QuicHeaderTestData.BuildShortHeader(0x24, [0xAA, 0xBB]);
        byte[] longPacket = BuildZeroRttLongHeaderPacket(
            [0x10, 0x11],
            [0x20],
            QuicHeaderTestData.BuildZeroRttVersionSpecificData([0x30], [0x40, 0x41]));

        Assert.True(QuicPacketParser.TryClassifyHeaderForm(shortPacket, out QuicHeaderForm shortHeaderForm));
        Assert.Equal(QuicHeaderForm.Short, shortHeaderForm);

        Assert.True(QuicPacketParser.TryClassifyHeaderForm(longPacket, out QuicHeaderForm longHeaderForm));
        Assert.Equal(QuicHeaderForm.Long, longHeaderForm);
    }

    [Fact]
    public void TryClassifyHeaderForm_RejectsEmptyInput()
    {
        Assert.False(QuicPacketParser.TryClassifyHeaderForm([], out _));
    }

    [Fact]
    public void TryParseLongHeader_ParsesAValidVersion1Packet()
    {
        byte[] destinationConnectionId = [0x10, 0x11];
        byte[] sourceConnectionId = [0x20];
        byte[] versionSpecificData = QuicHeaderTestData.BuildZeroRttVersionSpecificData([0x30], [0x40, 0x41]);
        byte[] packet = BuildZeroRttLongHeaderPacket(destinationConnectionId, sourceConnectionId, versionSpecificData);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(QuicHeaderForm.Long, header.HeaderForm);
        Assert.Equal((byte)0x50, header.HeaderControlBits);
        Assert.True(header.FixedBit);
        Assert.Equal((byte)0x01, header.LongPacketTypeBits);
        Assert.Equal(1u, header.Version);
        Assert.False(header.IsVersionNegotiation);
        Assert.Equal(2, header.DestinationConnectionIdLength);
        Assert.True(destinationConnectionId.AsSpan().SequenceEqual(header.DestinationConnectionId));
        Assert.Equal(1, header.SourceConnectionIdLength);
        Assert.True(sourceConnectionId.AsSpan().SequenceEqual(header.SourceConnectionId));
        Assert.True(versionSpecificData.AsSpan().SequenceEqual(header.VersionSpecificData));
    }

    [Fact]
    public void TryParseLongHeader_RejectsTruncatedBuffers()
    {
        byte[] versionSpecificData = QuicHeaderTestData.BuildZeroRttVersionSpecificData([0x30], [0x40, 0x41]);
        byte[] packet = QuicHeaderTestData.BuildTruncatedLongHeader(
            headerControlBits: 0x50,
            version: 1,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            versionSpecificData: versionSpecificData,
            truncateBy: 1);

        Assert.False(QuicPacketParser.TryParseLongHeader(packet, out _));
    }

    [Fact]
    public void TryParseLongHeader_RejectsVersion1ConnectionIdsLongerThan20Bytes()
    {
        byte[] versionSpecificData = QuicHeaderTestData.BuildZeroRttVersionSpecificData([0x30], [0x40, 0x41]);
        byte[] destinationTooLongPacket = BuildZeroRttLongHeaderPacket(new byte[21], [0x20], versionSpecificData);
        byte[] sourceTooLongPacket = BuildZeroRttLongHeaderPacket([0x10, 0x11], new byte[21], versionSpecificData);

        Assert.False(QuicPacketParser.TryParseLongHeader(destinationTooLongPacket, out _));
        Assert.False(QuicPacketParser.TryParseLongHeader(sourceTooLongPacket, out _));
    }

    [Fact]
    public void TryParseLongHeader_ParsesNonVersion1LongHeadersWithoutApplyingVersion1ConnectionIdLimit()
    {
        byte[] destinationConnectionId = new byte[21];
        byte[] sourceConnectionId = new byte[21];
        byte[] versionSpecificData = [0x11, 0x22, 0x33];
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x40,
            version: 0x11223344,
            destinationConnectionId: destinationConnectionId,
            sourceConnectionId: sourceConnectionId,
            versionSpecificData: versionSpecificData);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(0x11223344u, header.Version);
        Assert.Equal(destinationConnectionId.Length, header.DestinationConnectionIdLength);
        Assert.Equal(sourceConnectionId.Length, header.SourceConnectionIdLength);
        Assert.True(versionSpecificData.AsSpan().SequenceEqual(header.VersionSpecificData));
    }

    [Fact]
    public void TryGetLongHeaderPacketType_MapsVersion2PacketTypeBits()
    {
        Assert.True(QuicVersionNegotiation.TryGetLongHeaderPacketType(
            QuicVersionNegotiation.Version2,
            0x01,
            out QuicLongPacketType initialPacketType));
        Assert.Equal(QuicLongPacketType.Initial, initialPacketType);

        Assert.True(QuicVersionNegotiation.TryGetLongHeaderPacketType(
            QuicVersionNegotiation.Version2,
            0x02,
            out QuicLongPacketType zeroRttPacketType));
        Assert.Equal(QuicLongPacketType.ZeroRtt, zeroRttPacketType);

        Assert.True(QuicVersionNegotiation.TryGetLongHeaderPacketType(
            QuicVersionNegotiation.Version2,
            0x03,
            out QuicLongPacketType handshakePacketType));
        Assert.Equal(QuicLongPacketType.Handshake, handshakePacketType);

        Assert.True(QuicVersionNegotiation.TryGetLongHeaderPacketType(
            QuicVersionNegotiation.Version2,
            0x00,
            out QuicLongPacketType retryPacketType));
        Assert.Equal(QuicLongPacketType.Retry, retryPacketType);
    }

    [Fact]
    public void TryParseLongHeader_AcceptsVersion2InitialAndHandshakePackets()
    {
        byte[] initialPacket = BuildVersion2InitialPacket();
        byte[] handshakePacket = BuildVersion2HandshakePacket();

        Assert.True(QuicPacketParser.TryParseLongHeader(initialPacket, out QuicLongHeaderPacket initialHeader));
        Assert.Equal(QuicVersionNegotiation.Version2, initialHeader.Version);
        Assert.True(QuicVersionNegotiation.TryGetLongHeaderPacketType(
            initialHeader.Version,
            initialHeader.LongPacketTypeBits,
            out QuicLongPacketType initialPacketType));
        Assert.Equal(QuicLongPacketType.Initial, initialPacketType);

        Assert.True(QuicPacketParser.TryParseLongHeader(handshakePacket, out QuicLongHeaderPacket handshakeHeader));
        Assert.Equal(QuicVersionNegotiation.Version2, handshakeHeader.Version);
        Assert.True(QuicVersionNegotiation.TryGetLongHeaderPacketType(
            handshakeHeader.Version,
            handshakeHeader.LongPacketTypeBits,
            out QuicLongPacketType handshakePacketType));
        Assert.Equal(QuicLongPacketType.Handshake, handshakePacketType);
    }

    [Fact]
    public void TryGetPacketNumberSpace_RejectsVersion2RetryPackets()
    {
        byte[] retryPacket = BuildVersion2RetryPacket();

        Assert.True(QuicPacketParser.TryParseLongHeader(retryPacket, out QuicLongHeaderPacket header));
        Assert.Equal(QuicVersionNegotiation.Version2, header.Version);
        Assert.True(QuicVersionNegotiation.TryGetLongHeaderPacketType(
            header.Version,
            header.LongPacketTypeBits,
            out QuicLongPacketType packetType));
        Assert.Equal(QuicLongPacketType.Retry, packetType);
        Assert.False(QuicPacketParser.TryGetPacketNumberSpace(retryPacket, out _));
    }

    [Fact]
    public void TryGetPacketNumberSpace_MapsVersion2InitialAndHandshakePackets()
    {
        byte[] initialPacket = BuildVersion2InitialPacket();
        byte[] handshakePacket = BuildVersion2HandshakePacket();

        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(initialPacket, out QuicPacketNumberSpace initialSpace));
        Assert.Equal(QuicPacketNumberSpace.Initial, initialSpace);

        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(handshakePacket, out QuicPacketNumberSpace handshakeSpace));
        Assert.Equal(QuicPacketNumberSpace.Handshake, handshakeSpace);
    }

    [Fact]
    public void TryParseShortHeader_ParsesAValidShortHeaderPacket()
    {
        byte[] expectedRemainder = [0xAA, 0xBB, 0xCC];
        byte[] packet = QuicHeaderTestData.BuildShortHeader(0x24, [0xAA, 0xBB, 0xCC]);

        Assert.True(QuicPacketParser.TryParseShortHeader(packet, out QuicShortHeaderPacket header));
        Assert.Equal(QuicHeaderForm.Short, header.HeaderForm);
        Assert.Equal((byte)0x64, header.HeaderControlBits);
        Assert.True(header.FixedBit);
        Assert.True(header.SpinBit);
        Assert.True(header.KeyPhase);
        Assert.Equal((byte)0x00, header.PacketNumberLengthBits);
        Assert.True(expectedRemainder.AsSpan().SequenceEqual(header.Remainder));
    }

    [Fact]
    public void TryParseShortHeader_AllowsClearedFixedBitWhenExplicitlyEnabled()
    {
        byte[] expectedRemainder = [0xAA, 0xBB, 0xCC];
        byte[] packet = QuicHeaderTestData.BuildShortHeader(0x24, expectedRemainder);
        packet[0] = (byte)(packet[0] & ~QuicPacketHeaderBits.FixedBitMask);

        Assert.False(QuicPacketParser.TryParseShortHeader(packet, out _));

        Assert.True(QuicPacketParser.TryParseShortHeader(
            packet,
            allowClearedFixedBit: true,
            out QuicShortHeaderPacket header));
        Assert.Equal(QuicHeaderForm.Short, header.HeaderForm);
        Assert.Equal((byte)0x24, header.HeaderControlBits);
        Assert.False(header.FixedBit);
        Assert.True(header.SpinBit);
        Assert.True(header.KeyPhase);
        Assert.Equal((byte)0x00, header.PacketNumberLengthBits);
        Assert.True(expectedRemainder.AsSpan().SequenceEqual(header.Remainder));
    }

    [Fact]
    public void TryParseShortHeader_RejectsEmptyInput()
    {
        Assert.False(QuicPacketParser.TryParseShortHeader([], out _));
    }

    [Fact]
    public void TryParseVersionNegotiation_ParsesAValidVersionNegotiationPacket()
    {
        byte[] expectedDestinationConnectionId = [0x10, 0x11];
        byte[] expectedSourceConnectionId = [0x20];
        byte[] packet = QuicHeaderTestData.BuildVersionNegotiation(
            headerControlBits: 0x4C,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            supportedVersions: [0x11223344, 0xAABBCCDD]);

        Assert.True(QuicPacketParser.TryParseVersionNegotiation(packet, out QuicVersionNegotiationPacket header));
        Assert.Equal(QuicHeaderForm.Long, header.HeaderForm);
        Assert.Equal((byte)0x4C, header.HeaderControlBits);
        Assert.Equal(0u, header.Version);
        Assert.True(header.IsVersionNegotiation);
        Assert.Equal(2, header.DestinationConnectionIdLength);
        Assert.True(expectedDestinationConnectionId.AsSpan().SequenceEqual(header.DestinationConnectionId));
        Assert.Equal(1, header.SourceConnectionIdLength);
        Assert.True(expectedSourceConnectionId.AsSpan().SequenceEqual(header.SourceConnectionId));
        Assert.Equal(2, header.SupportedVersionCount);
        Assert.Equal((uint)0x11223344, header.GetSupportedVersion(0));
        Assert.Equal((uint)0xAABBCCDD, header.GetSupportedVersion(1));
    }

    [Fact]
    public void TryParseVersionNegotiation_RejectsTruncatedAndMalformedLayouts()
    {
        byte[] truncatedPacket = QuicHeaderTestData.BuildVersionNegotiation(
            headerControlBits: 0x4C,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            supportedVersions: [0x11223344])[..^1];

        byte[] emptyVersionListPacket = QuicHeaderTestData.BuildVersionNegotiation(
            headerControlBits: 0x4C,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20]);

        byte[] misalignedVersionListPacket = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x4C,
            version: 0,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            versionSpecificData: [0x11, 0x22, 0x33]);

        Assert.False(QuicPacketParser.TryParseVersionNegotiation(truncatedPacket, out _));
        Assert.False(QuicPacketParser.TryParseVersionNegotiation(emptyVersionListPacket, out _));
        Assert.False(QuicPacketParser.TryParseVersionNegotiation(misalignedVersionListPacket, out _));
    }

    [Fact]
    public void TryGetPacketLength_ReturnsTheLeadingLongHeaderPacketLengthWithinACoalescedDatagram()
    {
        byte[] firstVersionSpecificData = QuicHeaderTestData.BuildInitialVersionSpecificData(
            token: [0xA0],
            packetNumber: [0x01, 0x02],
            protectedPayload: [0xB0]);
        byte[] firstPacket = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x42,
            version: 1,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            versionSpecificData: firstVersionSpecificData);
        byte[] secondVersionSpecificData = QuicHeaderTestData.BuildZeroRttVersionSpecificData(
            packetNumber: [0x03, 0x04],
            protectedPayload: [0xC0]);
        byte[] secondPacket = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x62,
            version: 1,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            versionSpecificData: secondVersionSpecificData);
        byte[] datagram = [.. firstPacket, .. secondPacket];

        Assert.True(QuicPacketParser.TryGetPacketLength(datagram, out int firstPacketLength));
        Assert.Equal(firstPacket.Length, firstPacketLength);
        Assert.True(QuicPacketParser.TryGetPacketLength(datagram.AsSpan(firstPacketLength), out int secondPacketLength));
        Assert.Equal(secondPacket.Length, secondPacketLength);
    }

    [Fact]
    public void TryGetPacketLength_UsesTheRemainingDatagramForShortHeaderPackets()
    {
        byte[] shortHeaderPacket = QuicHeaderTestData.BuildShortHeader(0x24, [0xAA, 0xBB, 0xCC]);

        Assert.True(QuicPacketParser.TryGetPacketLength(shortHeaderPacket, out int packetLength));
        Assert.Equal(shortHeaderPacket.Length, packetLength);
    }

    [Fact]
    public void TryGetPacketLength_ReturnsTheWholeDatagramForNonVersion1LongHeaders()
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x40,
            version: 0x11223344,
            destinationConnectionId: new byte[21],
            sourceConnectionId: new byte[21],
            versionSpecificData: [0x11, 0x22, 0x33]);

        Assert.True(QuicPacketParser.TryGetPacketLength(packet, out int packetLength));
        Assert.Equal(packet.Length, packetLength);
    }

    private static byte[] BuildZeroRttLongHeaderPacket(
        byte[] destinationConnectionId,
        byte[] sourceConnectionId,
        byte[] versionSpecificData)
    {
        return QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x50,
            version: 1,
            destinationConnectionId: destinationConnectionId,
            sourceConnectionId: sourceConnectionId,
            versionSpecificData: versionSpecificData);
    }

    private static byte[] BuildVersion2InitialPacket()
    {
        return QuicHeaderTestData.BuildLongHeader(
            headerControlBits: (byte)(QuicPacketHeaderBits.FixedBitMask
                | (0x01 << QuicPacketHeaderBits.LongPacketTypeBitsShift)),
            version: QuicVersionNegotiation.Version2,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            versionSpecificData: QuicHeaderTestData.BuildInitialVersionSpecificData(
                [0x01],
                [0x02],
                [0xAA]));
    }

    private static byte[] BuildVersion2HandshakePacket()
    {
        return QuicHeaderTestData.BuildLongHeader(
            headerControlBits: (byte)(QuicPacketHeaderBits.FixedBitMask
                | (0x03 << QuicPacketHeaderBits.LongPacketTypeBitsShift)
                | 0x02),
            version: QuicVersionNegotiation.Version2,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            versionSpecificData: QuicHeaderTestData.BuildZeroRttVersionSpecificData(
                [0x01, 0x02],
                [0xAA, 0xBB]));
    }

    private static byte[] BuildVersion2RetryPacket()
    {
        return QuicRetryPacketRequirementTestData.BuildRetryPacket(
            version: QuicVersionNegotiation.Version2,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            retryToken: [0x74, 0x6F, 0x6B, 0x65, 0x6E]);
    }
}
