namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P2P3-0004")]
public sealed class REQ_QUIC_RFC9000_S17P2P3_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerCanAcceptEarlyDataAndRetainZeroRttMaterial()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateAcceptedFinishedClientRuntime(
            ticketMaxEarlyDataSize: 4_096,
            includeEarlyData: true);

        Assert.Equal(QuicTlsEarlyDataDisposition.Accepted, runtime.TlsState.PeerEarlyDataDisposition);
        Assert.False(runtime.TlsState.OldKeysDiscarded);
        Assert.True(runtime.TlsState.TryGetPacketProtectionMaterial(
            QuicTlsEncryptionLevel.ZeroRtt,
            out QuicTlsPacketProtectionMaterial zeroRttMaterial));
        Assert.Equal(QuicTlsEncryptionLevel.ZeroRtt, zeroRttMaterial.EncryptionLevel);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerCanRejectEarlyDataAndDiscardZeroRttMaterial()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateAcceptedFinishedClientRuntime(
            ticketMaxEarlyDataSize: 4_096,
            includeEarlyData: false);

        Assert.Equal(QuicTlsEarlyDataDisposition.Rejected, runtime.TlsState.PeerEarlyDataDisposition);
        Assert.True(runtime.TlsState.OldKeysDiscarded);
        Assert.False(runtime.TlsState.TryGetPacketProtectionMaterial(QuicTlsEncryptionLevel.ZeroRtt, out _));
    }
}
