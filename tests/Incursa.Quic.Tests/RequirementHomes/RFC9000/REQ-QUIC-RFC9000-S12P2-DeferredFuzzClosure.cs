// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S12P2_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S12P2-0002")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void LengthFieldFuzz_BoundsPacketNumberAndProtectedPayload()
    {
        Random random = new(0x5122_0002);

        for (int iteration = 0; iteration < 32; iteration++)
        {
            int packetNumberLength = 1 + (iteration % 4);
            int protectedPayloadLength = iteration % 9;
            byte[] packetNumber = QuicHeaderTestData.RandomBytes(random, packetNumberLength);
            byte[] protectedPayload = QuicHeaderTestData.RandomBytes(random, protectedPayloadLength);
            byte[] versionSpecificData = QuicHeaderTestData.BuildZeroRttVersionSpecificData(packetNumber, protectedPayload);
            byte[] packet = QuicHeaderTestData.BuildLongHeader(
                headerControlBits: (byte)(0x50 | (packetNumberLength - 1)),
                version: 1,
                destinationConnectionId: [(byte)(0x10 + iteration), 0x11],
                sourceConnectionId: [(byte)(0x20 + iteration)],
                versionSpecificData);
            byte[] trailingPacket = QuicHeaderTestData.BuildShortHeader(0x24, [(byte)(0x80 + iteration)]);
            byte[] datagram = [.. packet, .. trailingPacket];

            Assert.True(QuicPacketParser.TryGetPacketLength(datagram, out int leadingPacketLength));
            Assert.Equal(packet.Length, leadingPacketLength);
            Assert.True(QuicPacketParser.TryParseLongHeader(datagram[..leadingPacketLength], out QuicLongHeaderPacket header));
            Assert.True(versionSpecificData.AsSpan().SequenceEqual(header.VersionSpecificData));

            Assert.False(QuicPacketParser.TryGetPacketLength(packet[..^1], out _));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S12P2-0003")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void CoalescedDatagramFuzz_SeparatesLeadingLengthDelimitedPackets()
    {
        Random random = new(0x5122_0003);

        for (int iteration = 0; iteration < 32; iteration++)
        {
            byte[] token = QuicHeaderTestData.RandomBytes(random, iteration % 5);
            byte[] packetNumber = QuicHeaderTestData.RandomBytes(random, 1 + (iteration % 4));
            byte[] protectedPayload = QuicHeaderTestData.RandomBytes(random, 1 + (iteration % 7));
            byte[] firstVersionSpecificData = QuicHeaderTestData.BuildInitialVersionSpecificData(
                token,
                packetNumber,
                protectedPayload);
            byte[] firstPacket = QuicHeaderTestData.BuildLongHeader(
                headerControlBits: (byte)(0x40 | (packetNumber.Length - 1)),
                version: 1,
                destinationConnectionId: [(byte)(0x30 + iteration)],
                sourceConnectionId: [(byte)(0x40 + iteration), 0x41],
                firstVersionSpecificData);
            byte[] secondVersionSpecificData = QuicHeaderTestData.BuildZeroRttVersionSpecificData(
                packetNumber: [(byte)(0x50 + iteration)],
                protectedPayload: [(byte)(0x60 + iteration), 0x61]);
            byte[] secondPacket = QuicHeaderTestData.BuildLongHeader(
                headerControlBits: 0x50,
                version: 1,
                destinationConnectionId: [(byte)(0x70 + iteration)],
                sourceConnectionId: [(byte)(0x80 + iteration)],
                secondVersionSpecificData);
            byte[] datagram = [.. firstPacket, .. secondPacket];

            Assert.True(QuicPacketParser.TryGetPacketLength(datagram, out int firstPacketLength));
            Assert.Equal(firstPacket.Length, firstPacketLength);
            Assert.True(QuicPacketParser.TryGetPacketLength(datagram.AsSpan(firstPacketLength), out int secondPacketLength));
            Assert.Equal(secondPacket.Length, secondPacketLength);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S12P2-0006")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void SameEncryptionLevelFramePackingFuzz_RoundTripsMultipleFramesInOneProtectedPacket()
    {
        Assert.True(QuicS12P3TestSupport.TryCreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt,
            out QuicTlsPacketProtectionMaterial applicationMaterial));

        QuicHandshakeFlowCoordinator coordinator = new(
            new byte[] { 0x71, 0x72, 0x73, 0x74 },
            new byte[] { 0x81, 0x82, 0x83, 0x84 });

        for (int iteration = 0; iteration < 16; iteration++)
        {
            byte[] firstStreamData = [(byte)(0x10 + iteration), (byte)(0x20 + iteration)];
            byte[] secondStreamData = [(byte)(0x30 + iteration)];
            byte[] firstStreamFrame = QuicStreamTestData.BuildStreamFrame(
                0x0E,
                streamId: (ulong)(iteration * 4),
                firstStreamData);
            byte[] secondStreamFrame = QuicStreamTestData.BuildStreamFrame(
                0x0E,
                streamId: (ulong)(iteration * 4 + 4),
                secondStreamData);
            byte[] applicationPayload = [.. firstStreamFrame, .. secondStreamFrame];

            Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
                applicationPayload,
                applicationMaterial,
                out byte[] protectedPacket));
            Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
                protectedPacket,
                applicationMaterial,
                out byte[] openedPacket,
                out int payloadOffset,
                out int payloadLength,
                out bool keyPhase));
            Assert.False(keyPhase);

            ReadOnlySpan<byte> payload = openedPacket.AsSpan(payloadOffset, payloadLength);
            Assert.True(QuicStreamParser.TryParseStreamFrame(payload, out QuicStreamFrame firstFrame));
            Assert.Equal((ulong)(iteration * 4), firstFrame.StreamId.Value);
            Assert.True(firstStreamData.AsSpan().SequenceEqual(firstFrame.StreamData));

            ReadOnlySpan<byte> remainingPayload = payload[firstFrame.ConsumedLength..];
            Assert.True(QuicStreamParser.TryParseStreamFrame(remainingPayload, out QuicStreamFrame secondFrame));
            Assert.Equal((ulong)(iteration * 4 + 4), secondFrame.StreamId.Value);
            Assert.True(secondStreamData.AsSpan().SequenceEqual(secondFrame.StreamData));
            Assert.True(secondFrame.ConsumedLength <= remainingPayload.Length);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S12P2-0013")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void NonLengthBearingPacketFuzz_ConsumesWholeDatagramWhenTrailingBytesLookLikeAnotherPacket()
    {
        for (int iteration = 0; iteration < 16; iteration++)
        {
            byte[] trailingPacket = QuicHeaderTestData.BuildShortHeader(
                0x24,
                [(byte)(0x90 + iteration), (byte)(0xA0 + iteration), (byte)(0xB0 + iteration)]);
            byte[] retryPacket = QuicHeaderTestData.BuildLongHeader(
                headerControlBits: 0x73,
                version: 1,
                destinationConnectionId: [(byte)(0x10 + iteration)],
                sourceConnectionId: [(byte)(0x20 + iteration)],
                versionSpecificData: [(byte)(0x30 + iteration), 0x31, 0x32, 0x33]);
            byte[] retryDatagram = [.. retryPacket, .. trailingPacket];

            Assert.True(QuicPacketParser.TryGetPacketLength(retryDatagram, out int retryPacketLength));
            Assert.Equal(retryDatagram.Length, retryPacketLength);

            byte[] versionNegotiationPacket = QuicHeaderTestData.BuildVersionNegotiation(
                headerControlBits: (byte)(0x40 | (iteration & 0x0F)),
                destinationConnectionId: [(byte)(0x40 + iteration)],
                sourceConnectionId: [(byte)(0x50 + iteration)],
                supportedVersions: [0x1122_3300u + (uint)iteration]);
            byte[] versionNegotiationDatagram = [.. versionNegotiationPacket, .. trailingPacket];

            Assert.True(QuicPacketParser.TryGetPacketLength(versionNegotiationDatagram, out int versionNegotiationPacketLength));
            Assert.Equal(versionNegotiationDatagram.Length, versionNegotiationPacketLength);

            byte[] shortHeaderDatagram = QuicHeaderTestData.BuildShortHeader(
                0x24,
                [(byte)(0x60 + iteration), (byte)(0x70 + iteration), (byte)(0x80 + iteration), (byte)(0x90 + iteration)]);

            Assert.True(QuicPacketParser.TryGetPacketLength(shortHeaderDatagram, out int shortHeaderPacketLength));
            Assert.Equal(shortHeaderDatagram.Length, shortHeaderPacketLength);
        }
    }
}
