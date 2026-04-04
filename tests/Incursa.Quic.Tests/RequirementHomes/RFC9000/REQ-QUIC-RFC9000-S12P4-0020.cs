namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S12P4-0020">A frame type MUST use the shortest possible encoding.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S12P4-0020")]
public sealed class REQ_QUIC_RFC9000_S12P4_0020
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
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

    private static void AssertSingleByteFrameTypePrefix(byte[] encodedFrame, ulong expectedFrameType)
    {
        Assert.True(QuicVariableLengthInteger.TryParse(encodedFrame, out ulong frameType, out int bytesConsumed));
        Assert.Equal(expectedFrameType, frameType);
        Assert.Equal(1, bytesConsumed);
    }
}
