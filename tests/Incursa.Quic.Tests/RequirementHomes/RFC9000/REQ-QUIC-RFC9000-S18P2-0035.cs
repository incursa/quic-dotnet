namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S18P2-0035")]
public sealed class REQ_QUIC_RFC9000_S18P2_0035
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
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
