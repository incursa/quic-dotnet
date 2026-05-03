namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3P1-0021">The Packet Number field MUST be Packet Number field is 1 to 4 bytes long.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P3P1-0021")]
public sealed class REQ_QUIC_RFC9000_S17P3P1_0021
{
    public static TheoryData<int> PacketNumberLengthCases => new()
    {
        { 1 },
        { 2 },
        { 3 },
        { 4 },
    };

    [Theory]
    [MemberData(nameof(PacketNumberLengthCases))]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryOpenProtectedApplicationDataPacket_AllowsPacketNumberFieldsFromOneToFourBytes(int packetNumberLength)
    {
        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P3TestSupport.CreatePacketCoordinator();
        QuicTlsPacketProtectionMaterial material = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt);

        byte[] packetNumber = new byte[packetNumberLength];
        byte[] payload = QuicS12P3TestSupport.CreatePingPayload();

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
}
