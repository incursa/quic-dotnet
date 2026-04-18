namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P3P1-0009")]
public sealed class REQ_QUIC_RFC9000_S17P3P1_0009
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryBuildProtectedApplicationDataPacket_AcceptsTheMaximumConnectionIdLength()
    {
        byte[] destinationConnectionId = QuicS12P3TestSupport.CreateSequentialBytes(0x10, 20);
        QuicHandshakeFlowCoordinator coordinator = new(destinationConnectionId, ReadOnlyMemory<byte>.Empty);

        Assert.True(QuicS12P3TestSupport.TryCreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt,
            out QuicTlsPacketProtectionMaterial material));

        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            QuicS12P3TestSupport.CreatePingPayload(),
            material,
            out byte[] protectedPacket));

        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            material,
            out byte[] openedPacket,
            out int payloadOffset,
            out _));

        Assert.True(openedPacket.AsSpan(1, destinationConnectionId.Length).SequenceEqual(destinationConnectionId));
        Assert.Equal(1 + destinationConnectionId.Length + 4, payloadOffset);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryBuildProtectedApplicationDataPacket_RejectsConnectionIdsLongerThan160Bits()
    {
        byte[] destinationConnectionId = QuicS12P3TestSupport.CreateSequentialBytes(0x20, 21);
        QuicHandshakeFlowCoordinator coordinator = new(destinationConnectionId, ReadOnlyMemory<byte>.Empty);

        Assert.True(QuicS12P3TestSupport.TryCreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt,
            out QuicTlsPacketProtectionMaterial material));

        Assert.False(coordinator.TryBuildProtectedApplicationDataPacket(
            QuicS12P3TestSupport.CreatePingPayload(),
            material,
            out _));
    }
}
