namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S12P5-0007">A server MAY treat receipt of these frames in 0-RTT packets as a connection error of type PROTOCOL_VIOLATION.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S12P5-0007")]
public sealed class REQ_QUIC_RFC9000_S12P5_0007
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EndpointCanDiscardZeroRttPacketsContainingForbiddenFramesByLeavingThemUnrouted()
    {
        QuicTlsPacketProtectionMaterial zeroRttMaterial = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.ZeroRtt);
        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P3TestSupport.CreateBootstrapPacketCoordinator();

        byte[] zeroRttPayload =
        [
            .. QuicFrameTestData.BuildAckFrame(new QuicAckFrame
            {
                FrameType = 0x02,
                LargestAcknowledged = 0,
                AckDelay = 0,
                FirstAckRange = 0,
            }),
            .. QuicFrameTestData.BuildCryptoFrame(new QuicCryptoFrame(0, [0xAA])),
            .. QuicFrameTestData.BuildHandshakeDoneFrame(),
            .. QuicFrameTestData.BuildNewTokenFrame(new QuicNewTokenFrame([0xBB])),
            .. QuicFrameTestData.BuildPathResponseFrame(new QuicPathResponseFrame([1, 2, 3, 4, 5, 6, 7, 8])),
            .. QuicFrameTestData.BuildRetireConnectionIdFrame(new QuicRetireConnectionIdFrame(7)),
        ];

        Assert.True(coordinator.TryBuildProtectedZeroRttApplicationPacket(
            zeroRttPayload,
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
