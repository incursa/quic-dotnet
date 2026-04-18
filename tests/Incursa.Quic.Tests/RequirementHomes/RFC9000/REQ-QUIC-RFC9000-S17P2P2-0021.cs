namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0021">The client and server use the Initial packet type for any packet that MUST contain an initial cryptographic handshake message.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P2-0021")]
public sealed class REQ_QUIC_RFC9000_S17P2P2_0021
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0021">The client and server use the Initial packet type for any packet that MUST contain an initial cryptographic handshake message.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0021")]
    public void TryBuildProtectedInitialPackets_UseTheInitialPacketTypeForClientAndServerInitialCryptoMessages()
    {
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            QuicS17P2P2TestSupport.InitialDestinationConnectionId,
            out QuicInitialPacketProtection clientProtection));
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            QuicS17P2P2TestSupport.InitialDestinationConnectionId,
            out QuicInitialPacketProtection serverProtection));

        byte[] clientCryptoPayload = QuicS12P3TestSupport.CreateSequentialBytes(0x40, 20);
        QuicHandshakeFlowCoordinator clientCoordinator = QuicS17P2P2TestSupport.CreateClientCoordinator();
        Assert.True(clientCoordinator.TryBuildProtectedInitialPacket(
            clientCryptoPayload,
            cryptoPayloadOffset: 0,
            clientProtection,
            out byte[] clientProtectedPacket));
        Assert.True(clientCoordinator.TryOpenInitialPacket(
            clientProtectedPacket,
            serverProtection,
            out byte[] clientOpenedPacket,
            out int clientPayloadOffset,
            out int clientPayloadLength));

        QuicS17P2P2TestSupport.AssertOpenedInitialPacketContainsCryptoPayload(
            clientOpenedPacket,
            clientPayloadOffset,
            clientPayloadLength,
            clientCryptoPayload,
            expectedCryptoOffset: 0);

        byte[] serverCryptoPayload = QuicS12P3TestSupport.CreateSequentialBytes(0x50, 20);
        QuicHandshakeFlowCoordinator serverCoordinator = QuicS17P2P2TestSupport.CreateServerCoordinator();
        Assert.True(serverCoordinator.TrySetHandshakeDestinationConnectionId(QuicS17P2P2TestSupport.InitialSourceConnectionId));
        Assert.True(serverCoordinator.TryBuildProtectedInitialPacketForHandshakeDestination(
            serverCryptoPayload,
            cryptoPayloadOffset: 0,
            serverProtection,
            out byte[] serverProtectedPacket));
        Assert.True(serverCoordinator.TryOpenInitialPacket(
            serverProtectedPacket,
            clientProtection,
            out byte[] serverOpenedPacket,
            out int serverPayloadOffset,
            out int serverPayloadLength));

        QuicS17P2P2TestSupport.AssertOpenedInitialPacketContainsCryptoPayload(
            serverOpenedPacket,
            serverPayloadOffset,
            serverPayloadLength,
            serverCryptoPayload,
            expectedCryptoOffset: 0);
    }
}
