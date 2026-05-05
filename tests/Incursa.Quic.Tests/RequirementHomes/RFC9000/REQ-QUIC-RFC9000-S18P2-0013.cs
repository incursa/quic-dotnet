namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S18P2-0013")]
public sealed class REQ_QUIC_RFC9000_S18P2_0013
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0013")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatTransportParameters_EmitsInitialMaxStreamsUniAsAVarint()
    {
        QuicTransportParameters parameters = new()
        {
            InitialMaxStreamsUni = 3,
        };

        byte[] encoded = QuicS18P2InitialStreamLimitTestSupport.FormatTransportParameters(parameters);
        byte[] expected = QuicS18P2InitialStreamLimitTestSupport.BuildInitialStreamLimitParameter(
            QuicS18P2InitialStreamLimitTestSupport.InitialMaxStreamsUniId,
            3);

        Assert.Equal(expected, encoded);
        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            encoded,
            QuicTransportParameterRole.Client,
            out QuicTransportParameters parsed));
        Assert.Null(parsed.InitialMaxStreamsBidi);
        Assert.Equal(3UL, parsed.InitialMaxStreamsUni);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0013")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseTransportParameters_RejectsInitialMaxStreamsUniAboveTheSixtyBitLimit()
    {
        byte[] encoded = QuicS18P2InitialStreamLimitTestSupport.BuildInitialStreamLimitParameter(
            QuicS18P2InitialStreamLimitTestSupport.InitialMaxStreamsUniId,
            QuicS18P2InitialStreamLimitTestSupport.MaximumInitialStreamLimit + 1);

        Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
            encoded,
            QuicTransportParameterRole.Client,
            out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0013")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseTransportParameters_AcceptsInitialMaxStreamsUniAtTheSixtyBitLimit()
    {
        QuicTransportParameters parsed = QuicS18P2InitialStreamLimitTestSupport.ParseInitialStreamLimitParameter(
            QuicS18P2InitialStreamLimitTestSupport.InitialMaxStreamsUniId,
            QuicS18P2InitialStreamLimitTestSupport.MaximumInitialStreamLimit);

        Assert.Equal(QuicS18P2InitialStreamLimitTestSupport.MaximumInitialStreamLimit, parsed.InitialMaxStreamsUni);
    }
}
