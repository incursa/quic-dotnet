namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P2P1-0009">A client that is not yet certain that the server has finished validating its address MUST NOT reset the PTO backoff factor on receiving acknowledgments in Initial packets.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S6P2P1-0009")]
public sealed class REQ_QUIC_RFC9002_S6P2P1_0009
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ResetProbeTimeoutBackoffCount_DoesNotResetOnAnUnvalidatedInitialAcknowledgment()
    {
        Assert.Equal(3, QuicRecoveryTiming.ResetProbeTimeoutBackoffCount(
            ptoCount: 3,
            acknowledgmentReceived: true,
            acknowledgmentPacketNumberSpace: QuicPacketNumberSpace.Initial,
            handshakeConfirmed: false));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ResetProbeTimeoutBackoffCount_ResetsOnAValidatedInitialAcknowledgment()
    {
        Assert.Equal(0, QuicRecoveryTiming.ResetProbeTimeoutBackoffCount(
            ptoCount: 3,
            acknowledgmentReceived: true,
            acknowledgmentPacketNumberSpace: QuicPacketNumberSpace.Initial,
            handshakeConfirmed: true));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ResetProbeTimeoutBackoffCount_PreservesAZeroBackoffOnAnUnvalidatedInitialAcknowledgment()
    {
        Assert.Equal(0, QuicRecoveryTiming.ResetProbeTimeoutBackoffCount(
            ptoCount: 0,
            acknowledgmentReceived: true,
            acknowledgmentPacketNumberSpace: QuicPacketNumberSpace.Initial,
            handshakeConfirmed: false));
    }
}
