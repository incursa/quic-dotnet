namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P14-0004")]
public sealed class REQ_QUIC_RFC9000_S19P14_0004
{
    [Theory]
    [InlineData(true, 0x16UL)]
    [InlineData(false, 0x17UL)]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0004")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseStreamsBlockedFrame_ParsesType16And17AsOneByteVarints(
        bool isBidirectional,
        ulong expectedFrameType)
    {
        byte[] encoded = QuicS19P14StreamsBlockedFrameTestSupport.BuildStreamsBlockedFrame(isBidirectional);

        Assert.True(QuicVariableLengthInteger.TryParse(encoded, out ulong frameType, out int bytesConsumed));
        Assert.Equal(expectedFrameType, frameType);
        Assert.Equal(1, bytesConsumed);
        QuicS19P14StreamsBlockedFrameTestSupport.AssertParses(encoded, isBidirectional, expectedMaximumStreams: 16);
    }

    [Theory]
    [InlineData(0x15)]
    [InlineData(0x18)]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0004")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseStreamsBlockedFrame_RejectsTypeValuesOutside16And17(byte frameType)
    {
        byte[] encoded = QuicS19P14StreamsBlockedFrameTestSupport.BuildStreamsBlockedFrameWithEncodedType([frameType]);

        QuicS19P14StreamsBlockedFrameTestSupport.AssertRejects(encoded);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0004")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseStreamsBlockedFrame_RejectsNonMinimalType16And17Varints()
    {
        byte[][] encodedFrames =
        [
            QuicS19P14StreamsBlockedFrameTestSupport.BuildStreamsBlockedFrameWithEncodedType([0x40, 0x16]),
            QuicS19P14StreamsBlockedFrameTestSupport.BuildStreamsBlockedFrameWithEncodedType([0x40, 0x17]),
        ];

        foreach (byte[] encoded in encodedFrames)
        {
            QuicS19P14StreamsBlockedFrameTestSupport.AssertRejects(encoded);
        }
    }
}
