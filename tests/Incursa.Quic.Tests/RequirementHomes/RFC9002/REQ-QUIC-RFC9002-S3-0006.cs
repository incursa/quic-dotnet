namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-S3-0006")]
public sealed class REQ_QUIC_RFC9002_S3_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryBuildProtectedApplicationDataPacket_SendsPacketNumbersMonotonicallyWithinOneSpace()
    {
        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P3TestSupport.CreatePacketCoordinator();
        QuicTlsPacketProtectionMaterial material = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt);
        byte[] payload = QuicS17P2P3TestSupport.CreatePingPayload();
        ulong previousPacketNumber = 0;

        for (int index = 0; index < 4; index++)
        {
            Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
                payload,
                material,
                out ulong packetNumber,
                out byte[] protectedPacket));
            Assert.NotEmpty(protectedPacket);

            if (index > 0)
            {
                Assert.True(packetNumber > previousPacketNumber);
            }

            previousPacketNumber = packetNumber;
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryBuildProtectedApplicationDataPacketForRetransmission_DoesNotMoveBackwardForLowerFloors()
    {
        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P3TestSupport.CreatePacketCoordinator();
        QuicTlsPacketProtectionMaterial material = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt);
        byte[] payload = QuicS17P2P3TestSupport.CreatePingPayload();

        Assert.True(coordinator.TryBuildProtectedApplicationDataPacketForRetransmission(
            payload,
            minimumPacketNumberExclusive: 5,
            material,
            keyPhase: false,
            out ulong firstPacketNumber,
            out byte[] firstPacket));
        Assert.Equal(6UL, firstPacketNumber);
        Assert.NotEmpty(firstPacket);

        Assert.True(coordinator.TryBuildProtectedApplicationDataPacketForRetransmission(
            payload,
            minimumPacketNumberExclusive: 2,
            material,
            keyPhase: false,
            out ulong secondPacketNumber,
            out byte[] secondPacket));

        Assert.Equal(7UL, secondPacketNumber);
        Assert.NotEmpty(secondPacket);
        Assert.True(secondPacketNumber > firstPacketNumber);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryBuildProtectedApplicationDataPacketForRetransmission_SendsTheLastLegalPacketNumberBeforeStopping()
    {
        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P3TestSupport.CreatePacketCoordinator();
        QuicTlsPacketProtectionMaterial material = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt);
        byte[] payload = QuicS17P2P3TestSupport.CreatePingPayload();

        Assert.True(coordinator.TryBuildProtectedApplicationDataPacketForRetransmission(
            payload,
            minimumPacketNumberExclusive: QuicVariableLengthInteger.MaxValue - 2,
            material,
            keyPhase: false,
            out ulong finalPacketNumber,
            out byte[] finalPacket));

        Assert.Equal(QuicVariableLengthInteger.MaxValue - 1, finalPacketNumber);
        Assert.NotEmpty(finalPacket);

        Assert.False(coordinator.TryBuildProtectedApplicationDataPacket(
            payload,
            material,
            out _,
            out byte[] rejectedPacket));
        Assert.Empty(rejectedPacket);
    }
}
