namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S5-0007")]
public sealed class REQ_QUIC_RFC9000_S5_0007
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S5-0007")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerCanSendApplicationDataBeforePeerHandshakeTranscriptCompletes()
    {
        using QuicConnectionRuntime runtime = QuicS19P20HandshakeDoneTestSupport.CreateServerRuntimeReadyToEvaluateHandshakeDoneSend();

        Assert.False(runtime.PeerHandshakeTranscriptCompleted);
        Assert.False(runtime.HandshakeConfirmed);
        Assert.True(runtime.TlsState.OneRttProtectPacketProtectionMaterial.HasValue);

        byte[] applicationPayload = QuicStreamTestData.BuildStreamFrame(
            0x0E,
            streamId: 1,
            [0x11, 0x22],
            offset: 0);

        QuicHandshakeFlowCoordinator coordinator = new(runtime.CurrentPeerDestinationConnectionId.ToArray());
        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            applicationPayload,
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            runtime.TlsState.CurrentOneRttKeyPhaseBit,
            out byte[] protectedPacket));

        Assert.False(runtime.PeerHandshakeTranscriptCompleted);
        Assert.False(runtime.HandshakeConfirmed);
        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(protectedPacket, out QuicPacketNumberSpace packetNumberSpace));
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, packetNumberSpace);
    }
}
