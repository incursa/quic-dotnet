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
}
