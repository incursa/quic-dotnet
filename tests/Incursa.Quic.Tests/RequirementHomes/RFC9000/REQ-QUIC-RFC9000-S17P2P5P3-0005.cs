namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P2P5P3-0005")]
public sealed class REQ_QUIC_RFC9000_S17P2P5P3_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientZeroRttPacketsUseTheRetrySourceConnectionIdAfterItIsApplied()
    {
        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P5P2TestSupport.CreateClientCoordinator();
        Assert.True(coordinator.TrySetHandshakeDestinationConnectionId(QuicS17P2P5P2TestSupport.RetrySourceConnectionId));

        QuicTlsPacketProtectionMaterial zeroRttMaterial = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.ZeroRtt);

        Assert.True(coordinator.TryBuildProtectedZeroRttApplicationPacket(
            QuicS17P2P3TestSupport.CreatePingPayload(),
            zeroRttMaterial,
            out ulong packetNumber,
            out byte[] protectedPacket));

        Assert.Equal(0UL, packetNumber);
        Assert.True(QuicPacketParsing.TryParseLongHeaderFields(
            protectedPacket,
            out _,
            out uint version,
            out ReadOnlySpan<byte> destinationConnectionId,
            out _,
            out _));
        Assert.Equal((uint)1, version);
        Assert.Equal(QuicS17P2P5P2TestSupport.RetrySourceConnectionId, destinationConnectionId.ToArray());
    }
}
