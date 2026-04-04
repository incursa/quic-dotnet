namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-S6P2P1-0008")]
public sealed class REQ_QUIC_RFC9002_S6P2P1_0008
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ResetProbeTimeoutBackoffCount_ResetsTheBackoffAfterAnAcknowledgment()
    {
        Assert.Equal(0, QuicRecoveryTiming.ResetProbeTimeoutBackoffCount(
            ptoCount: 4,
            acknowledgmentReceived: true,
            acknowledgmentPacketNumberSpace: QuicPacketNumberSpace.ApplicationData,
            handshakeConfirmed: false));
    }
}
