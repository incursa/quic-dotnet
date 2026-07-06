// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S17-1-P4-R01">After an acknowledgment is received for a packet number space, the sender MUST use a packet number size able to represent more than twice as large a range as the difference between the largest acknowledged packet number and the packet number being sent.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S17-1-P4-R01")]
public sealed class REQ_QUIC_RFC9000_S17P1_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryBuildProtectedApplicationDataPacket_UsesFourBytePacketNumbersAfterAnAcknowledgment()
    {
        Assert.True(QuicS12P3TestSupport.TryCreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt,
            out QuicTlsPacketProtectionMaterial applicationMaterial));

        QuicHandshakeFlowCoordinator coordinator = QuicS17P1TestSupport.CreateApplicationCoordinator();
        QuicConnectionSendRuntime sendRuntime = new();
        byte[] payload = QuicS12P3TestSupport.CreatePingPayload();

        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            payload,
            applicationMaterial,
            out ulong firstPacketNumber,
            out byte[] firstProtectedPacket));

        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            firstProtectedPacket,
            applicationMaterial,
            out byte[] firstOpenedPacket,
            out int firstPayloadOffset,
            out _));
        Assert.True(QuicPacketParser.TryParseShortHeader(firstOpenedPacket, out QuicShortHeaderPacket firstHeader));
        Assert.Equal(4, firstHeader.PacketNumberLengthBits + 1);
        Assert.Equal(firstPacketNumber, QuicS17P1TestSupport.ReadPacketNumber(
            firstOpenedPacket.AsSpan(firstPayloadOffset - 4, 4)));

        sendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            firstPacketNumber,
            (ulong)firstProtectedPacket.Length,
            SentAtMicros: 0,
            PacketBytes: firstProtectedPacket));
        Assert.True(sendRuntime.TryAcknowledgePacket(QuicPacketNumberSpace.ApplicationData, firstPacketNumber));

        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            payload,
            applicationMaterial,
            out ulong secondPacketNumber,
            out byte[] secondProtectedPacket));

        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            secondProtectedPacket,
            applicationMaterial,
            out byte[] secondOpenedPacket,
            out int secondPayloadOffset,
            out _));
        Assert.True(QuicPacketParser.TryParseShortHeader(secondOpenedPacket, out QuicShortHeaderPacket secondHeader));
        Assert.Equal(4, secondHeader.PacketNumberLengthBits + 1);
        Assert.Equal(secondPacketNumber, QuicS17P1TestSupport.ReadPacketNumber(
            secondOpenedPacket.AsSpan(secondPayloadOffset - 4, 4)));

        Assert.Equal(0UL, firstPacketNumber);
        Assert.Equal(1UL, secondPacketNumber);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryOpenProtectedApplicationDataPacket_RejectsTruncatedPackets()
    {
        Assert.True(QuicS12P3TestSupport.TryCreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt,
            out QuicTlsPacketProtectionMaterial applicationMaterial));

        QuicHandshakeFlowCoordinator coordinator = QuicS17P1TestSupport.CreateApplicationCoordinator();
        byte[] payload = QuicS12P3TestSupport.CreatePingPayload();

        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            payload,
            applicationMaterial,
            out byte[] protectedPacket));

        Assert.False(coordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket[..^1],
            applicationMaterial,
            out _,
            out _,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryBuildProtectedApplicationDataPacket_UsesLargestFourByteSafeRangeAfterAcknowledgment()
    {
        Assert.True(QuicS12P3TestSupport.TryCreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt,
            out QuicTlsPacketProtectionMaterial applicationMaterial));

        const ulong largestAcknowledgedPacketNumber = 0;
        const ulong largestDifferenceRepresentableByFourBytes = (1UL << 31) - 1;
        ulong expectedPacketNumber = largestAcknowledgedPacketNumber + largestDifferenceRepresentableByFourBytes;

        QuicHandshakeFlowCoordinator coordinator = QuicS17P1TestSupport.CreateApplicationCoordinator();
        QuicConnectionSendRuntime sendRuntime = new();
        byte[] payload = QuicS12P3TestSupport.CreatePingPayload();

        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            payload,
            applicationMaterial,
            out ulong firstPacketNumber,
            out byte[] firstProtectedPacket));
        Assert.Equal(largestAcknowledgedPacketNumber, firstPacketNumber);

        sendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            firstPacketNumber,
            (ulong)firstProtectedPacket.Length,
            SentAtMicros: 0,
            PacketBytes: firstProtectedPacket));
        Assert.True(sendRuntime.TryAcknowledgePacket(QuicPacketNumberSpace.ApplicationData, firstPacketNumber));

        Assert.True(coordinator.TryBuildProtectedApplicationDataPacketForRetransmission(
            payload,
            minimumPacketNumberExclusive: expectedPacketNumber - 1,
            applicationMaterial,
            keyPhase: false,
            out ulong packetNumber,
            out byte[] protectedPacket));

        Assert.Equal(expectedPacketNumber, packetNumber);
        QuicS17P1TestSupport.AssertOpenedApplicationPacketNumber(
            coordinator,
            protectedPacket,
            applicationMaterial,
            packetNumber);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void TryBuildProtectedApplicationDataPacket_UsesRecoverablePacketNumberLengthsAcrossAcknowledgedRanges()
    {
        Assert.True(QuicS12P3TestSupport.TryCreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt,
            out QuicTlsPacketProtectionMaterial applicationMaterial));

        ulong[] minimumPacketNumbersExclusive =
        [
            0UL,
            1UL,
            255UL,
            256UL,
            65_535UL,
            65_536UL,
            uint.MaxValue - 2UL,
        ];

        foreach (ulong minimumPacketNumberExclusive in minimumPacketNumbersExclusive)
        {
            QuicHandshakeFlowCoordinator coordinator = QuicS17P1TestSupport.CreateApplicationCoordinator();
            QuicConnectionSendRuntime sendRuntime = new();
            byte[] payload = QuicS12P3TestSupport.CreatePingPayload();

            Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
                payload,
                applicationMaterial,
                out ulong firstPacketNumber,
                out byte[] firstProtectedPacket));

            sendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
                QuicPacketNumberSpace.ApplicationData,
                firstPacketNumber,
                (ulong)firstProtectedPacket.Length,
                SentAtMicros: 0,
                PacketBytes: firstProtectedPacket));
            Assert.True(sendRuntime.TryAcknowledgePacket(QuicPacketNumberSpace.ApplicationData, firstPacketNumber));

            Assert.True(coordinator.TryBuildProtectedApplicationDataPacketForRetransmission(
                payload,
                minimumPacketNumberExclusive,
                applicationMaterial,
                keyPhase: false,
                out ulong packetNumber,
                out byte[] protectedPacket));

            Assert.Equal(minimumPacketNumberExclusive + 1, packetNumber);
            QuicS17P1TestSupport.AssertOpenedApplicationPacketNumber(
                coordinator,
                protectedPacket,
                applicationMaterial,
                packetNumber);
        }
    }
}
