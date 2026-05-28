// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S12P2-0006">An endpoint SHOULD include multiple frames in a single packet if they are to be sent at the same encryption level, instead of coalescing multiple packets at the same encryption level.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S12P2-0006")]
public sealed class REQ_QUIC_RFC9000_S12P2_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryBuildProtectedApplicationDataPacket_CanCarryMultipleStreamFramesAtTheSameEncryptionLevel()
    {
        Assert.True(QuicS12P3TestSupport.TryCreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt,
            out QuicTlsPacketProtectionMaterial applicationMaterial));

        byte[] firstStreamFrame = QuicStreamTestData.BuildStreamFrame(
            0x0E,
            streamId: 0,
            [0xA1]);
        byte[] secondStreamFrame = QuicStreamTestData.BuildStreamFrame(
            0x0E,
            streamId: 4,
            [0xB1, 0xB2]);
        byte[] applicationPayload = [.. firstStreamFrame, .. secondStreamFrame];

        QuicHandshakeFlowCoordinator coordinator = new(
            new byte[] { 0x31, 0x32, 0x33, 0x34 },
            new byte[] { 0x41, 0x42, 0x43, 0x44 });

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
        Assert.Equal(0UL, firstFrame.StreamId.Value);
        Assert.True(firstFrame.StreamData.SequenceEqual(new byte[] { 0xA1 }));

        ReadOnlySpan<byte> remainingPayload = payload[firstFrame.ConsumedLength..];
        Assert.True(QuicStreamParser.TryParseStreamFrame(remainingPayload, out QuicStreamFrame secondFrame));
        Assert.Equal(4UL, secondFrame.StreamId.Value);
        Assert.True(secondFrame.StreamData.SequenceEqual(new byte[] { 0xB1, 0xB2 }));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseShortHeader_TreatsASecondApplicationPacketAtTheSameEncryptionLevelAsOpaqueTrailingData()
    {
        Assert.True(QuicS12P3TestSupport.TryCreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt,
            out QuicTlsPacketProtectionMaterial applicationMaterial));

        byte[] firstStreamFrame = QuicStreamTestData.BuildStreamFrame(
            0x0E,
            streamId: 0,
            [0xC1]);
        byte[] secondStreamFrame = QuicStreamTestData.BuildStreamFrame(
            0x0E,
            streamId: 4,
            [0xD1]);
        byte[] trailingStreamFrame = QuicStreamTestData.BuildStreamFrame(
            0x0E,
            streamId: 8,
            [0xE1]);
        byte[] firstApplicationPayload = [.. firstStreamFrame, .. secondStreamFrame];

        QuicHandshakeFlowCoordinator coordinator = new(
            new byte[] { 0x51, 0x52, 0x53, 0x54 },
            new byte[] { 0x61, 0x62, 0x63, 0x64 });

        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            firstApplicationPayload,
            applicationMaterial,
            out byte[] firstProtectedPacket));
        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            trailingStreamFrame,
            applicationMaterial,
            out byte[] trailingProtectedPacket));

        byte[] datagram = [.. firstProtectedPacket, .. trailingProtectedPacket];

        Assert.True(QuicPacketParser.TryGetPacketLength(datagram, out int combinedPacketLength));
        Assert.Equal(datagram.Length, combinedPacketLength);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryBuildProtectedApplicationDataPacket_CanCarryTheSmallestMultiFramePayloadAtThePacketBoundary()
    {
        Assert.True(QuicS12P3TestSupport.TryCreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt,
            out QuicTlsPacketProtectionMaterial applicationMaterial));

        byte[] firstStreamFrame = QuicStreamTestData.BuildStreamFrame(
            0x0E,
            streamId: 1,
            [0x11]);
        byte[] secondStreamFrame = QuicStreamTestData.BuildStreamFrame(
            0x0E,
            streamId: 5,
            [0x22]);
        byte[] applicationPayload = [.. firstStreamFrame, .. secondStreamFrame];

        QuicHandshakeFlowCoordinator coordinator = new(
            new byte[] { 0x71, 0x72, 0x73, 0x74 },
            new byte[] { 0x81, 0x82, 0x83, 0x84 });

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
        Assert.True(firstFrame.StreamData.SequenceEqual(new byte[] { 0x11 }));
        ReadOnlySpan<byte> remainingPayload = payload[firstFrame.ConsumedLength..];
        Assert.True(QuicStreamParser.TryParseStreamFrame(remainingPayload, out QuicStreamFrame secondFrame));
        Assert.True(secondFrame.StreamData.SequenceEqual(new byte[] { 0x22 }));
    }
}
