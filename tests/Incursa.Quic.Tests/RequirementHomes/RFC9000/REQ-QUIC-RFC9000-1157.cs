namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-1157">The value of the active_connection_id_limit parameter MUST be at least 2.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-1157")]
public sealed class REQ_QUIC_RFC9000_1157
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseTransportParameters_AcceptsMinimumActiveConnectionIdLimit()
    {
        byte[] encoded = QuicTransportParameterTestData.BuildTransportParameterTuple(
            0x0E,
            QuicVarintTestData.EncodeMinimal(2));

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            encoded,
            QuicTransportParameterRole.Client,
            out QuicTransportParameters parsed));
        Assert.Equal(2UL, parsed.ActiveConnectionIdLimit);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseTransportParameters_RejectsActiveConnectionIdLimitBelowTwo()
    {
        byte[] encoded = QuicTransportParameterTestData.BuildTransportParameterTuple(
            0x0E,
            QuicVarintTestData.EncodeMinimal(1));

        Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
            encoded,
            QuicTransportParameterRole.Client,
            out _));
    }
}
