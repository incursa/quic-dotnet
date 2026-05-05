namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P10-0007")]
public sealed class REQ_QUIC_RFC9000_S19P10_0007
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseMaxStreamDataFrame_ParsesMaximumStreamDataAsVarint()
    {
        ulong maximumStreamData = 0x1234_5678;
        byte[] encoded = QuicS19P10MaxStreamDataFrameTestSupport.BuildMaxStreamDataFrame(streamId: 1, maximumStreamData);

        QuicS19P10MaxStreamDataFrameTestSupport.AssertParses(encoded, expectedStreamId: 1, expectedMaximumStreamData: maximumStreamData);
        QuicS19P10MaxStreamDataFrameTestSupport.AssertFormats(new QuicMaxStreamDataFrame(1, maximumStreamData), encoded);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseMaxStreamDataFrame_RejectsTruncatedMaximumStreamDataVarint()
    {
        byte[] encoded = QuicS19P10MaxStreamDataFrameTestSupport.BuildMaxStreamDataFrameWithEncodedMaximumStreamData([0x40]);

        QuicS19P10MaxStreamDataFrameTestSupport.AssertRejects(encoded);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseMaxStreamDataFrame_PreservesMaximumVarintMaximumStreamData()
    {
        ulong maximumStreamData = QuicVariableLengthInteger.MaxValue;
        byte[] encoded = QuicS19P10MaxStreamDataFrameTestSupport.BuildMaxStreamDataFrame(streamId: 1, maximumStreamData);

        QuicS19P10MaxStreamDataFrameTestSupport.AssertParses(encoded, expectedStreamId: 1, expectedMaximumStreamData: maximumStreamData);
        QuicS19P10MaxStreamDataFrameTestSupport.AssertFormats(new QuicMaxStreamDataFrame(1, maximumStreamData), encoded);
    }
}
