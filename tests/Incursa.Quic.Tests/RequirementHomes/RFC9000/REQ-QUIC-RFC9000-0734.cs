namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0734">A frame type MUST use the shortest possible encoding.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-0734")]
public sealed class REQ_QUIC_RFC9000_0734
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatSelectedFrames_UsesSingleByteFrameTypeEncodings()
    {
        byte[] ping = QuicFrameTestData.BuildPingFrame();
        AssertSingleByteFrameTypePrefix(ping, 0x01);

        byte[] ack = QuicFrameTestData.BuildAckFrame(new QuicAckFrame
        {
            FrameType = 0x02,
            LargestAcknowledged = 0x09,
            AckDelay = 0x01,
            FirstAckRange = 0x00,
        });
        AssertSingleByteFrameTypePrefix(ack, 0x02);

        byte[] maxStreams = QuicFrameTestData.BuildMaxStreamsFrame(new QuicMaxStreamsFrame(isBidirectional: true, maximumStreams: 0x22));
        AssertSingleByteFrameTypePrefix(maxStreams, 0x12);

        byte[] connectionClose = QuicFrameTestData.BuildConnectionCloseFrame(new QuicConnectionCloseFrame(QuicTransportErrorCode.ProtocolViolation, triggeringFrameType: 0x02, reasonPhrase: []));
        AssertSingleByteFrameTypePrefix(connectionClose, 0x1C);
    }

    [Theory]
    [InlineData(2)]
    [InlineData(4)]
    [InlineData(8)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParsePingFrame_RejectsOverlongFrameTypeEncodings(int encodedLength)
    {
        byte[] encoded = QuicVarintTestData.EncodeWithLength(0x01, encodedLength);

        Assert.False(QuicFrameCodec.TryParsePingFrame(encoded, out _));
    }

    [Theory]
    [InlineData(2)]
    [InlineData(4)]
    [InlineData(8)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseMaxDataFrame_RejectsOverlongFrameTypeEncodings(int encodedLength)
    {
        byte[] encoded = [.. QuicVarintTestData.EncodeWithLength(0x10, encodedLength), 0x01];

        Assert.False(QuicFrameCodec.TryParseMaxDataFrame(encoded, out _, out _));
    }

    private static void AssertSingleByteFrameTypePrefix(byte[] encodedFrame, ulong expectedFrameType)
    {
        Assert.True(QuicVariableLengthInteger.TryParse(encodedFrame, out ulong frameType, out int bytesConsumed));
        Assert.Equal(expectedFrameType, frameType);
        Assert.Equal(1, bytesConsumed);
    }
}
