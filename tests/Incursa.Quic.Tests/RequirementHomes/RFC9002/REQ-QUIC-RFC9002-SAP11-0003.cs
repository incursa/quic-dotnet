namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-SAP11-0003")]
public sealed class REQ_QUIC_RFC9002_SAP11_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ResetProbeTimeoutBackoffCount_ResetsTheBackoffWhenKeysAreDiscarded()
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
