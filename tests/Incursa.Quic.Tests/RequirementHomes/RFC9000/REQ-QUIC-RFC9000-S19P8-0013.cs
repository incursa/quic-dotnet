namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P8-0013")]
public sealed class REQ_QUIC_RFC9000_S19P8_0013
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseStreamFrame_ReportsTheNamedStreamId()
    {
        QuicStreamFrame frame = QuicS19P8StreamFrameTestSupport.Parse(
            frameType: 0x0A,
            streamId: 0x1234,
            streamData: [0xAA]);

        Assert.Equal(0x1234UL, frame.StreamId.Value);
        Assert.Equal(QuicStreamType.Bidirectional, frame.StreamType);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseStreamFrame_RejectsMissingStreamIdField()
    {
        QuicS19P8StreamFrameTestSupport.AssertRejects([0x08]);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryParseStreamFrame_ReportsLargestStreamId()
    {
        QuicStreamFrame frame = QuicS19P8StreamFrameTestSupport.Parse(
            frameType: 0x0A,
            streamId: QuicVariableLengthInteger.MaxValue,
            streamData: []);

        Assert.Equal(QuicVariableLengthInteger.MaxValue, frame.StreamId.Value);
        Assert.Equal(QuicStreamType.Unidirectional, frame.StreamType);
    }
}
