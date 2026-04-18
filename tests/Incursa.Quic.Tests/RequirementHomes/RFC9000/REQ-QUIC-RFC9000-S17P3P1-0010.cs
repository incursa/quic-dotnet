namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P3P1-0010")]
public sealed class REQ_QUIC_RFC9000_S17P3P1_0010
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryBuildProtectedApplicationDataPacket_UsesAFourBytePacketNumberField()
    {
        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P3TestSupport.CreatePacketCoordinator();
        QuicTlsPacketProtectionMaterial material = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt);

        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            QuicS12P3TestSupport.CreatePingPayload(),
            material,
            out ulong packetNumber,
            out byte[] protectedPacket));

        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            material,
            out byte[] openedPacket,
            out int payloadOffset,
            out _));

        Assert.True(QuicPacketParser.TryParseShortHeader(openedPacket, out QuicShortHeaderPacket header));
        Assert.Equal(4, header.PacketNumberLengthBits + 1);
        Assert.Equal(packetNumber, QuicS17P1TestSupport.ReadPacketNumber(
            openedPacket.AsSpan(payloadOffset - 4, 4)));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(4)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryOpenProtectedApplicationDataPacket_AcceptsTheBoundaryPacketNumberFieldLengths(
        int packetNumberLength)
    {
        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P3TestSupport.CreatePacketCoordinator();
        QuicTlsPacketProtectionMaterial material = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt);
        byte[] payload = QuicS12P3TestSupport.CreatePingPayload();
        byte[] packetNumber = new byte[packetNumberLength];

        byte[] protectedPacket = QuicS17P3P1TestSupport.CreateProtectedApplicationDataPacket(
            QuicS17P2P3TestSupport.PacketConnectionId,
            packetNumber,
            payload,
            material,
            declaredPacketNumberLength: packetNumberLength);

        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            material,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength));

        Assert.True(QuicPacketParser.TryParseShortHeader(openedPacket, out QuicShortHeaderPacket header));
        Assert.Equal((byte)(packetNumberLength - 1), header.PacketNumberLengthBits);
        Assert.Equal(1 + QuicS17P2P3TestSupport.PacketConnectionId.Length + packetNumberLength, payloadOffset);
        Assert.Equal(0UL, QuicS17P1TestSupport.ReadPacketNumber(
            openedPacket.AsSpan(payloadOffset - packetNumberLength, packetNumberLength)));
        Assert.True(payloadLength >= payload.Length);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryOpenProtectedApplicationDataPacket_RejectsPacketNumberLengthMismatches()
    {
        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P3TestSupport.CreatePacketCoordinator();
        QuicTlsPacketProtectionMaterial material = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt);

        byte[] protectedPacket = QuicS17P3P1TestSupport.CreateProtectedApplicationDataPacket(
            QuicS17P2P3TestSupport.PacketConnectionId,
            [0x00],
            QuicS12P3TestSupport.CreatePingPayload(),
            material,
            declaredPacketNumberLength: 4);

        Assert.False(coordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            material,
            out _,
            out _,
            out _));
    }
}
