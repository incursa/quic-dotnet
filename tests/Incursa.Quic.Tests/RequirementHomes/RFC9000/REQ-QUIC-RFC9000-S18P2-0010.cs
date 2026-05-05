namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S18P2-0010")]
public sealed class REQ_QUIC_RFC9000_S18P2_0010
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0010")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatTransportParameters_EmitsInitialMaxStreamsBidiAsAVarint()
    {
        QuicTransportParameters parameters = new()
        {
            InitialMaxStreamsBidi = 4,
        };

        byte[] encoded = QuicS18P2InitialStreamLimitTestSupport.FormatTransportParameters(parameters);
        byte[] expected = QuicS18P2InitialStreamLimitTestSupport.BuildInitialStreamLimitParameter(
            QuicS18P2InitialStreamLimitTestSupport.InitialMaxStreamsBidiId,
            4);

        Assert.Equal(expected, encoded);
        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            encoded,
            QuicTransportParameterRole.Client,
            out QuicTransportParameters parsed));
        Assert.Equal(4UL, parsed.InitialMaxStreamsBidi);
        Assert.Null(parsed.InitialMaxStreamsUni);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0010")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseTransportParameters_RejectsInitialMaxStreamsBidiAboveTheSixtyBitLimit()
    {
        byte[] encoded = QuicS18P2InitialStreamLimitTestSupport.BuildInitialStreamLimitParameter(
            QuicS18P2InitialStreamLimitTestSupport.InitialMaxStreamsBidiId,
            QuicS18P2InitialStreamLimitTestSupport.MaximumInitialStreamLimit + 1);

        Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
            encoded,
            QuicTransportParameterRole.Client,
            out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0010")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseTransportParameters_AcceptsInitialMaxStreamsBidiAtTheSixtyBitLimit()
    {
        QuicTransportParameters parsed = QuicS18P2InitialStreamLimitTestSupport.ParseInitialStreamLimitParameter(
            QuicS18P2InitialStreamLimitTestSupport.InitialMaxStreamsBidiId,
            QuicS18P2InitialStreamLimitTestSupport.MaximumInitialStreamLimit);

        Assert.Equal(QuicS18P2InitialStreamLimitTestSupport.MaximumInitialStreamLimit, parsed.InitialMaxStreamsBidi);
    }
}
