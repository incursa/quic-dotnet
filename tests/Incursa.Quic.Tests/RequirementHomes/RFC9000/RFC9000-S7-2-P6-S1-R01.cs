// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S7-2-P6-S1-R01")]
public sealed class RFC9000_S7_2_P6_S1_R01
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ZeroRttFirstFlightUsesTheSameConnectionIdsAsTheFirstInitial()
    {
        (byte[] initialPacket, byte[] zeroRttPacket) =
            QuicS7P2FirstFlightConnectionIdTestSupport.BuildInitialAndZeroRttPackets(
                QuicS7P2FirstFlightConnectionIdTestSupport.InitialDestinationConnectionId,
                QuicS7P2FirstFlightConnectionIdTestSupport.InitialSourceConnectionId);

        Assert.True(QuicPacketParser.TryParseLongHeader(initialPacket, out QuicLongHeaderPacket initialHeader));
        Assert.True(QuicPacketParser.TryParseLongHeader(zeroRttPacket, out QuicLongHeaderPacket zeroRttHeader));
        Assert.True(initialHeader.DestinationConnectionId.SequenceEqual(zeroRttHeader.DestinationConnectionId));
        Assert.True(initialHeader.SourceConnectionId.SequenceEqual(zeroRttHeader.SourceConnectionId));
        Assert.True(zeroRttHeader.DestinationConnectionId.SequenceEqual(QuicS7P2FirstFlightConnectionIdTestSupport.InitialDestinationConnectionId));
        Assert.True(zeroRttHeader.SourceConnectionId.SequenceEqual(QuicS7P2FirstFlightConnectionIdTestSupport.InitialSourceConnectionId));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ZeroRttPacketCannotBeBuiltWithoutAFirstInitialDestinationConnectionId()
    {
        QuicHandshakeFlowCoordinator coordinator = new(
            initialDestinationConnectionId: ReadOnlyMemory<byte>.Empty,
            sourceConnectionId: QuicS7P2FirstFlightConnectionIdTestSupport.InitialSourceConnectionId);
        QuicTlsPacketProtectionMaterial zeroRttMaterial =
            QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(QuicTlsEncryptionLevel.ZeroRtt);

        Assert.False(coordinator.TryBuildProtectedZeroRttApplicationPacket(
            QuicS17P2P3TestSupport.CreatePingPayload(),
            zeroRttMaterial,
            out _,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ZeroRttFirstFlightCanStayAlignedWhenTheClientSourceConnectionIdIsAtTheMaximumLength()
    {
        byte[] maximumSourceConnectionId =
        [
            0x30, 0x31, 0x32, 0x33,
            0x34, 0x35, 0x36, 0x37,
            0x38, 0x39, 0x3A, 0x3B,
            0x3C, 0x3D, 0x3E, 0x3F,
            0x40, 0x41, 0x42, 0x43,
        ];
        (byte[] initialPacket, byte[] zeroRttPacket) =
            QuicS7P2FirstFlightConnectionIdTestSupport.BuildInitialAndZeroRttPackets(
                QuicS7P2FirstFlightConnectionIdTestSupport.InitialDestinationConnectionId,
                maximumSourceConnectionId);

        Assert.True(QuicPacketParser.TryParseLongHeader(initialPacket, out QuicLongHeaderPacket initialHeader));
        Assert.True(QuicPacketParser.TryParseLongHeader(zeroRttPacket, out QuicLongHeaderPacket zeroRttHeader));
        Assert.Equal(8, zeroRttHeader.DestinationConnectionId.Length);
        Assert.True(initialHeader.DestinationConnectionId.SequenceEqual(zeroRttHeader.DestinationConnectionId));
        Assert.Equal(20, zeroRttHeader.SourceConnectionId.Length);
        Assert.True(initialHeader.SourceConnectionId.SequenceEqual(zeroRttHeader.SourceConnectionId));
        Assert.True(zeroRttHeader.SourceConnectionId.SequenceEqual(maximumSourceConnectionId));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ZeroRttFirstFlightFuzz_UsesTheSameConnectionIdsAsTheFirstInitial()
    {
        byte[][] sourceConnectionIds =
        [
            [0x31],
            [0x32, 0x33, 0x34, 0x35],
            [0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D],
            [0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B],
        ];

        foreach (byte[] sourceConnectionId in sourceConnectionIds)
        {
            (byte[] initialPacket, byte[] zeroRttPacket) =
                QuicS7P2FirstFlightConnectionIdTestSupport.BuildInitialAndZeroRttPackets(
                    QuicS7P2FirstFlightConnectionIdTestSupport.InitialDestinationConnectionId,
                    sourceConnectionId);

            Assert.True(QuicPacketParser.TryParseLongHeader(initialPacket, out QuicLongHeaderPacket initialHeader));
            Assert.True(QuicPacketParser.TryParseLongHeader(zeroRttPacket, out QuicLongHeaderPacket zeroRttHeader));
            Assert.True(initialHeader.DestinationConnectionId.SequenceEqual(zeroRttHeader.DestinationConnectionId));
            Assert.True(initialHeader.SourceConnectionId.SequenceEqual(zeroRttHeader.SourceConnectionId));
            Assert.True(zeroRttHeader.SourceConnectionId.SequenceEqual(sourceConnectionId));
        }
    }
}
