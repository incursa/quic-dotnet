namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-SAP7-0005">If peer address validation is complete, the sender MUST reset pto_count to 0 after processing acknowledgments.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-SAP7-0005")]
public sealed class REQ_QUIC_RFC9002_SAP7_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ComputeProbeTimeoutWithBackoffMicros_UsesTheBasePtoAfterTheBackoffIsReset()
    {
        Assert.Equal(2_500UL, QuicRecoveryTiming.ComputeProbeTimeoutWithBackoffMicros(
            probeTimeoutMicros: 2_500,
            ptoCount: 0));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ComputeProbeTimeoutWithBackoffMicros_DoublesThePtoWhenTheBackoffHasNotBeenReset()
    {
        Assert.Equal(5_000UL, QuicRecoveryTiming.ComputeProbeTimeoutWithBackoffMicros(
            probeTimeoutMicros: 2_500,
            ptoCount: 1));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ComputeProbeTimeoutWithBackoffMicros_SaturatesWhenTheBackoffWouldOverflow()
    {
        Assert.Equal(ulong.MaxValue, QuicRecoveryTiming.ComputeProbeTimeoutWithBackoffMicros(
            probeTimeoutMicros: (ulong.MaxValue / 2) + 1,
            ptoCount: 1));
    }
}
