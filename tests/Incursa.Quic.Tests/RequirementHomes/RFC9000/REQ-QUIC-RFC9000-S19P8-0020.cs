namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P8-0020")]
public sealed class REQ_QUIC_RFC9000_S19P8_0020
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryReceiveStreamFrame_TreatsReceiveCreditExcessAsFlowControlError()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(connectionReceiveLimit: 1);
        QuicStreamFrame frame = QuicS19P8StreamFrameTestSupport.Parse(0x0A, streamId: 0x01, streamData: [0xAA, 0xBB]);

        Assert.False(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(QuicTransportErrorCode.FlowControlError, errorCode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryParseStreamFrame_AcceptsLargestOffsetThatDoesNotExceedStreamCeiling()
    {
        QuicStreamFrame frame = QuicS19P8StreamFrameTestSupport.Parse(
            frameType: 0x0C,
            streamId: 0x00,
            streamData: [],
            offset: QuicVariableLengthInteger.MaxValue);

        Assert.Equal(QuicVariableLengthInteger.MaxValue, frame.Offset);
        Assert.Equal(0, frame.StreamDataLength);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseStreamFrame_RejectsOffsetsThatExceedTheStreamCeiling()
    {
        Span<byte> offsetEncoding = stackalloc byte[8];
        Assert.True(QuicVariableLengthInteger.TryFormat(QuicVariableLengthInteger.MaxValue, offsetEncoding, out int offsetBytes));

        Span<byte> lengthEncoding = stackalloc byte[8];
        Assert.True(QuicVariableLengthInteger.TryFormat(1, lengthEncoding, out int lengthBytes));

        byte[] packet = new byte[1 + 1 + offsetBytes + lengthBytes + 1];
        int index = 0;
        packet[index++] = 0x0F;
        packet[index++] = 0x00;
        offsetEncoding[..offsetBytes].CopyTo(packet.AsSpan(index));
        index += offsetBytes;
        lengthEncoding[..lengthBytes].CopyTo(packet.AsSpan(index));
        index += lengthBytes;
        packet[index] = 0xFF;

        Assert.False(QuicStreamParser.TryParseStreamFrame(packet, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseStreamFrame_RejectsOffsetsThatExceedTheStreamCeilingWithoutALengthField()
    {
        byte[] packet = QuicStreamTestData.BuildStreamFrame(
            frameType: 0x0C,
            streamId: 0x00,
            streamData: [0xEF],
            offset: QuicVariableLengthInteger.MaxValue);

        Assert.False(QuicStreamParser.TryParseStreamFrame(packet, out _));
    }
}
