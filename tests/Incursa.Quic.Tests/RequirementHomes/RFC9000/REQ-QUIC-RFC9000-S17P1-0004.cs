namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P1-0004">An endpoint SHOULD use a large enough packet number encoding to allow the packet number to be recovered even if the packet arrives after packets that are sent afterwards.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P1-0004")]
public sealed class REQ_QUIC_RFC9000_S17P1_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryBuildProtectedApplicationDataPacket_AllowsPacketNumberRecoveryWhenPacketsArriveOutOfOrder()
    {
        Assert.True(QuicS12P3TestSupport.TryCreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt,
            out QuicTlsPacketProtectionMaterial applicationMaterial));

        QuicHandshakeFlowCoordinator coordinator = QuicS17P1TestSupport.CreateApplicationCoordinator();
        byte[] payload = QuicS12P3TestSupport.CreatePingPayload();

        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            payload,
            applicationMaterial,
            out ulong firstPacketNumber,
            out byte[] firstProtectedPacket));
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

        Assert.Equal(0UL, firstPacketNumber);
        Assert.Equal(1UL, secondPacketNumber);
    }
}
