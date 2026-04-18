namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0020">This protection does not provide confidentiality or integrity against attackers that can observe packets, but it does prevent attackers that MUST NOT observe packets from spoofing Initial packets.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P2-0020")]
public sealed class REQ_QUIC_RFC9000_S17P2P2_0020
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0020">This protection does not provide confidentiality or integrity against attackers that can observe packets, but it does prevent attackers that MUST NOT observe packets from spoofing Initial packets.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0020")]
    public void TryOpenInitialPacket_RejectsPacketsProtectedWithTheWrongInitialDcid()
    {
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            QuicS17P2P2TestSupport.InitialDestinationConnectionId,
            out QuicInitialPacketProtection clientProtection));
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            QuicS17P2P2TestSupport.InitialDestinationConnectionId,
            out QuicInitialPacketProtection serverProtection));
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE],
            out QuicInitialPacketProtection spoofedProtection));

        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P2TestSupport.CreateClientCoordinator();
        byte[] cryptoPayload = QuicS12P3TestSupport.CreateSequentialBytes(0x30, 20);

        Assert.True(coordinator.TryBuildProtectedInitialPacket(
            cryptoPayload,
            cryptoPayloadOffset: 0,
            clientProtection,
            out byte[] protectedPacket));

        Assert.False(coordinator.TryOpenInitialPacket(
            protectedPacket,
            spoofedProtection,
            out _,
            out _,
            out _));

        Assert.True(coordinator.TryOpenInitialPacket(
            protectedPacket,
            serverProtection,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength));

        QuicS17P2P2TestSupport.AssertOpenedInitialPacketContainsCryptoPayload(
            openedPacket,
            payloadOffset,
            payloadLength,
            cryptoPayload,
            expectedCryptoOffset: 0);
    }
}
