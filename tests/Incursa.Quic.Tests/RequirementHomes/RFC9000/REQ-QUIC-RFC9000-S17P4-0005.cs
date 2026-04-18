namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P4-0005">Even when the spin bit is not disabled by the administrator, endpoints MUST disable their use of the spin bit for a random selection of at least one in every 16 network paths, or for one in every 16 connection IDs, in order to ensure that QUIC connections that disable the spin bit are commonly observed on the network.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P4-0005")]
public sealed class REQ_QUIC_RFC9000_S17P4_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryBuildProtectedApplicationDataPacket_DisablesTheSpinBitForOneInSixteenConnectionIds()
    {
        QuicTlsPacketProtectionMaterial material = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt);
        byte[] payload = QuicS12P3TestSupport.CreatePingPayload();

        int disabledCount = 0;
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

            QuicHandshakeFlowCoordinator coordinator = new(
                destinationConnectionId,
                sourceConnectionId,
                enableRandomizedSpinBitSelection: true);

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
            Assert.Equal(QuicHeaderForm.Short, header.HeaderForm);
            Assert.Equal(1 + destinationConnectionId.Length + 4, payloadOffset);
            Assert.True(payloadLength >= payload.Length);
            Assert.True(openedPacket.AsSpan(payloadOffset, payload.Length).SequenceEqual(payload));

            if (!header.SpinBit)
            {
                disabledCount++;
            }
        }

        Assert.Equal(1, disabledCount);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryBuildProtectedApplicationDataPacket_LeavesTheSpinBitEnabledOutsideTheSelectionFloor()
    {
        QuicTlsPacketProtectionMaterial material = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt);
        byte[] payload = QuicS12P3TestSupport.CreatePingPayload();

        byte[] destinationConnectionId = [0x11, 0x31];
        byte[] sourceConnectionId = [0x51];

        QuicHandshakeFlowCoordinator coordinator = new(
            destinationConnectionId,
            sourceConnectionId,
            enableRandomizedSpinBitSelection: true);

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
        Assert.True(header.SpinBit);
        Assert.Equal(1 + destinationConnectionId.Length + 4, payloadOffset);
        Assert.True(payloadLength >= payload.Length);
    }
}
