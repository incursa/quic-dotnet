namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P2P2-0005">When Initial or Handshake keys are discarded, the PTO and loss detection timers MUST be reset.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S6P2P2-0005")]
public sealed class REQ_QUIC_RFC9002_S6P2P2_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ResetProbeTimeoutBackoffCount_ResetsTheBackoffWhenInitialOrHandshakeKeysAreDiscarded()
    {
        Assert.Equal(0, QuicRecoveryTiming.ResetProbeTimeoutBackoffCount(
            ptoCount: 3,
            initialOrHandshakeKeysDiscarded: true));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ResetProbeTimeoutBackoffCount_LeavesTheBackoffUnchangedWhenNoDiscardOccurs()
    {
        Assert.Equal(3, QuicRecoveryTiming.ResetProbeTimeoutBackoffCount(ptoCount: 3));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ResetProbeTimeoutBackoffCount_PreservesAZeroBackoffWhenKeysAreDiscarded()
    {
        Assert.Equal(0, QuicRecoveryTiming.ResetProbeTimeoutBackoffCount(
            ptoCount: 0,
            initialOrHandshakeKeysDiscarded: true));
    }
}
