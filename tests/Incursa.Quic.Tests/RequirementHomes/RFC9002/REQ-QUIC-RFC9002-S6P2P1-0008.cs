namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P2P1-0008">The PTO backoff factor MUST be reset when an acknowledgment is received.</workbench-requirement>
/// </workbench-requirements>
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
