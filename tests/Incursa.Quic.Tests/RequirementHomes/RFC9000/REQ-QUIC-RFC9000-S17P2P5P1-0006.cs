namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5P1-0006">A server MAY either discard or buffer 0-RTT packets that it receives.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P5P1-0006")]
public sealed class REQ_QUIC_RFC9000_S17P2P5P1_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5P1-0006">A server MAY either discard or buffer 0-RTT packets that it receives.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P5P1-0006")]
    public void EndpointCanDiscardZeroRttPacketsByLeavingThemUnrouted()
    {
        QuicTlsPacketProtectionMaterial zeroRttMaterial = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.ZeroRtt);
        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P3TestSupport.CreateBootstrapPacketCoordinator();

        Assert.True(coordinator.TryBuildProtectedZeroRttApplicationPacket(
            QuicS17P2P3TestSupport.CreatePingPayload(),
            zeroRttMaterial,
            out byte[] zeroRttPacket));
        Assert.True(QuicPacketParser.TryParseLongHeader(zeroRttPacket, out QuicLongHeaderPacket longHeader));
        Assert.Equal(QuicLongPacketTypeBits.ZeroRtt, longHeader.LongPacketTypeBits);
        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(
            zeroRttPacket,
            out QuicPacketNumberSpace packetNumberSpace));
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, packetNumberSpace);

        using QuicConnectionRuntimeEndpoint endpoint = new(1);
        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(
            zeroRttPacket,
            new QuicConnectionPathIdentity("203.0.113.10", "198.51.100.20", 443, 12345));

        Assert.Equal(QuicConnectionIngressDisposition.Unroutable, result.Disposition);
        Assert.Equal(QuicConnectionEndpointHandlingKind.None, result.HandlingKind);
        Assert.Null(result.Handle);
    }
}
