namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P1-0003">After an acknowledgment is received for a packet number space, the sender MUST use a packet number size able to represent more than twice as large a range as the difference between the largest acknowledged packet number and the packet number being sent.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P1-0003")]
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
}
