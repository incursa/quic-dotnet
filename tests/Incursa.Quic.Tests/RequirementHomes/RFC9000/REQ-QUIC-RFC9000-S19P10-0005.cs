namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P10-0005")]
public sealed class REQ_QUIC_RFC9000_S19P10_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseMaxStreamDataFrame_AcceptsType0x11()
    {
        byte[] encoded = QuicS19P10MaxStreamDataFrameTestSupport.BuildMaxStreamDataFrame(streamId: 0x06, maximumStreamData: 0x1234);

        Assert.Equal(QuicS19P10MaxStreamDataFrameTestSupport.MaxStreamDataFrameType, encoded[0]);
        QuicS19P10MaxStreamDataFrameTestSupport.AssertParses(encoded, expectedStreamId: 0x06, expectedMaximumStreamData: 0x1234);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseMaxStreamDataFrame_RejectsOtherFrameTypes()
    {
        byte[] encoded = QuicS19P10MaxStreamDataFrameTestSupport.BuildMaxStreamDataFrameWithEncodedType([0x10]);

        QuicS19P10MaxStreamDataFrameTestSupport.AssertRejects(encoded);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseMaxStreamDataFrame_RejectsNonMinimalTypeEncoding()
    {
        byte[] encoded = QuicS19P10MaxStreamDataFrameTestSupport.BuildMaxStreamDataFrameWithEncodedType([0x40, 0x11]);

        QuicS19P10MaxStreamDataFrameTestSupport.AssertRejects(encoded);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void Fuzz_MaxStreamDataFrameType_RoundTripsRepresentativeShapesAndRejectsTruncation()
    {
        QuicFrameCodecFuzzSupport.FuzzMaxStreamDataFrame();
    }
}
