namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P3P1-0011")]
public sealed class REQ_QUIC_RFC9000_S17P3P1_0011
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryOpenProtectedApplicationDataPacket_PreservesTheRequiredShortHeaderFields()
    {
        byte[] destinationConnectionId = QuicS17P2P3TestSupport.PacketConnectionId;
        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P3TestSupport.CreatePacketCoordinator();
        QuicTlsPacketProtectionMaterial material = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt);
        byte[] payload = QuicS12P3TestSupport.CreatePingPayload();

        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            payload,
            material,
            out ulong packetNumber,
            out byte[] protectedPacket));

        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            material,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength));

        Assert.True(QuicPacketParser.TryParseShortHeader(openedPacket, out QuicShortHeaderPacket header));
        Assert.Equal(QuicHeaderForm.Short, header.HeaderForm);
        Assert.True(header.FixedBit);
        Assert.Equal(4, header.PacketNumberLengthBits + 1);
        Assert.True(openedPacket.AsSpan(1, destinationConnectionId.Length).SequenceEqual(destinationConnectionId));
        Assert.Equal(1 + destinationConnectionId.Length + 4, payloadOffset);
        Assert.True(payloadLength >= payload.Length);
        Assert.Equal(packetNumber, QuicS17P1TestSupport.ReadPacketNumber(
            openedPacket.AsSpan(payloadOffset - 4, 4)));
    }
}
