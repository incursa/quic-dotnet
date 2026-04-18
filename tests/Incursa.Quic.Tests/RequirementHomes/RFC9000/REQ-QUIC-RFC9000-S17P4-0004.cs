namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P4-0004">Implementations MUST allow administrators of clients and servers to disable the spin bit either globally or on a per-connection basis.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P4-0004")]
public sealed class REQ_QUIC_RFC9000_S17P4_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryBuildProtectedApplicationDataPacket_DisablesTheSpinBitForSeparateConnections()
    {
        QuicTlsPacketProtectionMaterial material = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt);
        byte[] payload = QuicS12P3TestSupport.CreatePingPayload();

        byte[] firstDestinationConnectionId = [0x10, 0x11, 0x12];
        byte[] firstSourceConnectionId = [0x20, 0x21, 0x22];
        byte[] secondDestinationConnectionId = [0x30, 0x31, 0x32];
        byte[] secondSourceConnectionId = [0x40, 0x41, 0x42];

        QuicHandshakeFlowCoordinator firstCoordinator = new(firstDestinationConnectionId, firstSourceConnectionId);
        QuicHandshakeFlowCoordinator secondCoordinator = new(secondDestinationConnectionId, secondSourceConnectionId);

        AssertSpinBitRemainsDisabled(firstCoordinator, material, payload, firstDestinationConnectionId.Length);
        AssertSpinBitRemainsDisabled(secondCoordinator, material, payload, secondDestinationConnectionId.Length);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [Trait("Category", "Edge")]
    public void TryBuildProtectedApplicationDataPacket_DisablesTheSpinBitAcrossRepresentativeConnectionIds()
    {
        QuicTlsPacketProtectionMaterial material = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt);
        byte[] payload = QuicS12P3TestSupport.CreatePingPayload();

        for (int connectionIndex = 0; connectionIndex < 16; connectionIndex++)
        {
            byte[] destinationConnectionId =
            [
                (byte)(0x10 + connectionIndex),
                (byte)(0x30 + connectionIndex),
            ];

            byte[] sourceConnectionId =
            [
                (byte)(0x50 + connectionIndex),
            ];

            QuicHandshakeFlowCoordinator coordinator = new(destinationConnectionId, sourceConnectionId);

            AssertSpinBitRemainsDisabled(coordinator, material, payload, destinationConnectionId.Length);
        }
    }

    private static void AssertSpinBitRemainsDisabled(
        QuicHandshakeFlowCoordinator coordinator,
        QuicTlsPacketProtectionMaterial material,
        ReadOnlySpan<byte> payload,
        int destinationConnectionIdLength)
    {
        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            payload,
            material,
            out byte[] protectedPacket));

        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            material,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength));

        Assert.True(QuicPacketParser.TryParseShortHeader(openedPacket, out QuicShortHeaderPacket header));
        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(openedPacket, out QuicPacketNumberSpace packetNumberSpace));

        Assert.Equal(QuicHeaderForm.Short, header.HeaderForm);
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, packetNumberSpace);
        Assert.False(header.SpinBit);
        Assert.Equal(1 + destinationConnectionIdLength + 4, payloadOffset);
        Assert.True(payloadLength >= payload.Length);
        Assert.True(openedPacket.AsSpan(payloadOffset, payload.Length).SequenceEqual(payload));
        Assert.Equal(0UL, QuicS17P1TestSupport.ReadPacketNumber(openedPacket.AsSpan(payloadOffset - 4, 4)));
    }
}
