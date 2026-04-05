namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1-0015">When an endpoint uses a non-zero-length connection ID, it MUST ensure that the peer has a supply of connection IDs from which to choose for packets sent to the endpoint.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S5P1-0015")]
public sealed class REQ_QUIC_RFC9000_S5P1_0015
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1-0015">When an endpoint uses a non-zero-length connection ID, it MUST ensure that the peer has a supply of connection IDs from which to choose for packets sent to the endpoint.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S5P1-0015")]
    public void TryFormatTransportParameters_AdvertisesActiveConnectionIdLimit()
    {
        QuicTransportParameters parameters = new()
        {
            ActiveConnectionIdLimit = 8,
        };

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            QuicTransportParameterRole.Client,
            destination,
            out int bytesWritten));

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            destination[..bytesWritten],
            QuicTransportParameterRole.Server,
            out QuicTransportParameters parsed));

        Assert.Equal(8UL, parsed.ActiveConnectionIdLimit);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1-0015">When an endpoint uses a non-zero-length connection ID, it MUST ensure that the peer has a supply of connection IDs from which to choose for packets sent to the endpoint.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S5P1-0015")]
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

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1-0015">When an endpoint uses a non-zero-length connection ID, it MUST ensure that the peer has a supply of connection IDs from which to choose for packets sent to the endpoint.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S5P1-0015")]
    public void TryParseTransportParameters_AcceptsMinimumActiveConnectionIdLimit()
    {
        QuicTransportParameters parameters = new()
        {
            ActiveConnectionIdLimit = 2,
        };

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            QuicTransportParameterRole.Client,
            destination,
            out int bytesWritten));

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            destination[..bytesWritten],
            QuicTransportParameterRole.Server,
            out QuicTransportParameters parsed));

        Assert.Equal(2UL, parsed.ActiveConnectionIdLimit);
    }
}
