// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class RFC9002_S3_P1_DeferredFuzzClosure
{
    [Fact]
    [Requirement("RFC9002-S3-P1-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_LongHeaderTypeBitsIndicateEncryptionLevel()
    {
        foreach ((byte longPacketTypeBits, byte[] versionSpecificData) in new[]
        {
            (QuicLongPacketTypeBits.Initial, QuicHeaderTestData.BuildInitialVersionSpecificData([], [0xA1], [0xB2])),
            (QuicLongPacketTypeBits.ZeroRtt, QuicHeaderTestData.BuildZeroRttVersionSpecificData([0xA1], [0xB2])),
            (QuicLongPacketTypeBits.Handshake, QuicHeaderTestData.BuildZeroRttVersionSpecificData([0xA1], [0xB2])),
        })
        {
            byte[] packet = QuicHeaderTestData.BuildLongHeader(
                (byte)(QuicPacketHeaderBits.FixedBitMask | (longPacketTypeBits << QuicPacketHeaderBits.LongPacketTypeBitsShift)),
                version: 1,
                destinationConnectionId: [0x01, 0x02],
                sourceConnectionId: [0xA0, 0xA1],
                versionSpecificData);

            Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
            Assert.Equal(longPacketTypeBits, header.LongPacketTypeBits);
        }
    }

    [Fact]
    [Requirement("RFC9002-S3-P1-S1-R02")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ShortHeadersCarryPacketNumberBytes()
    {
        foreach ((byte packetNumberLengthBits, byte[] packetNumberBytes) in new[]
        {
            ((byte)0x00, new byte[] { 0x01 }),
            ((byte)0x01, new byte[] { 0xAA, 0xBB }),
            ((byte)0x02, new byte[] { 0x10, 0x20, 0x30 }),
            ((byte)0x03, new byte[] { 0xC0, 0xC1, 0xC2, 0xC3 }),
        })
        {
            byte[] packet = QuicHeaderTestData.BuildShortHeader(packetNumberLengthBits, packetNumberBytes);

            Assert.True(QuicPacketParser.TryParseShortHeader(packet, out QuicShortHeaderPacket header));
            Assert.Equal(packetNumberLengthBits, header.PacketNumberLengthBits);
            Assert.True(packetNumberBytes.AsSpan().SequenceEqual(header.Remainder));
        }
    }

    [Fact]
    [Requirement("RFC9002-S3-P1-S3-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ProtectedPacketBuilderDoesNotReusePacketNumbers()
    {
        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P3TestSupport.CreatePacketCoordinator();
        QuicTlsPacketProtectionMaterial material = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt);
        byte[] payload = QuicS17P2P3TestSupport.CreatePingPayload();
        HashSet<ulong> packetNumbers = [];

        foreach (int minimumPacketNumberExclusive in new[] { -1, 0, 2, 5, 5, 9 })
        {
            bool built = minimumPacketNumberExclusive < 0
                ? coordinator.TryBuildProtectedApplicationDataPacket(payload, material, out ulong packetNumber, out byte[] protectedPacket)
                : coordinator.TryBuildProtectedApplicationDataPacketForRetransmission(
                    payload,
                    (ulong)minimumPacketNumberExclusive,
                    material,
                    keyPhase: false,
                    out packetNumber,
                    out protectedPacket);

            Assert.True(built);
            Assert.NotEmpty(protectedPacket);
            Assert.True(packetNumbers.Add(packetNumber));
        }
    }

    [Fact]
    [Requirement("RFC9002-S3-P1-S4-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ProtectedPacketBuilderSendsPacketNumbersMonotonically()
    {
        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P3TestSupport.CreatePacketCoordinator();
        QuicTlsPacketProtectionMaterial material = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt);
        byte[] payload = QuicS17P2P3TestSupport.CreatePingPayload();
        ulong previousPacketNumber = 0;
        bool hasPreviousPacketNumber = false;

        foreach (int minimumPacketNumberExclusive in new[] { -1, 0, 2, 5, 5, 9 })
        {
            bool built = minimumPacketNumberExclusive < 0
                ? coordinator.TryBuildProtectedApplicationDataPacket(payload, material, out ulong packetNumber, out byte[] protectedPacket)
                : coordinator.TryBuildProtectedApplicationDataPacketForRetransmission(
                    payload,
                    (ulong)minimumPacketNumberExclusive,
                    material,
                    keyPhase: false,
                    out packetNumber,
                    out protectedPacket);

            Assert.True(built);
            Assert.NotEmpty(protectedPacket);
            if (hasPreviousPacketNumber)
            {
                Assert.True(packetNumber > previousPacketNumber);
            }

            previousPacketNumber = packetNumber;
            hasPreviousPacketNumber = true;
        }
    }

    [Fact]
    [Requirement("RFC9002-S3-P1-S4-R02")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AckGenerationRetainsIntentionalPacketNumberGaps()
    {
        foreach (ulong[] packetNumbers in new[]
        {
            new[] { 1UL, 3UL },
            new[] { 2UL, 5UL, 8UL },
            new[] { 10UL, 11UL, 15UL },
        })
        {
            QuicAckGenerationState tracker = new();
            foreach (ulong packetNumber in packetNumbers)
            {
                tracker.RecordProcessedPacket(
                    QuicPacketNumberSpace.ApplicationData,
                    packetNumber,
                    ackEliciting: true,
                    receivedAtMicros: 1_000 + packetNumber);
            }

            Assert.True(tracker.TryBuildAckFrame(
                QuicPacketNumberSpace.ApplicationData,
                nowMicros: 2_000,
                out QuicAckFrame frame));

            Assert.Equal(packetNumbers[^1], frame.LargestAcknowledged);
            Assert.NotEmpty(frame.AdditionalRanges);
            Assert.Contains(frame.AdditionalRanges, range => range.SmallestAcknowledged == packetNumbers[0]);
        }
    }
}
