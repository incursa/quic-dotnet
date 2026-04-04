namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S12P4-0008">The Frame Type in ACK, STREAM, MAX_STREAMS, STREAMS_BLOCKED, and CONNECTION_CLOSE frames MUST be used to carry other frame-specific flags.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S12P4-0008")]
public sealed class REQ_QUIC_RFC9000_S12P4_0008
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void FrameTypeCarriesTheDefinedFlagsForFlagBearingFrames()
    {
        QuicAckFrame ackFrame = new()
        {
            FrameType = 0x03,
            LargestAcknowledged = 0x21,
            AckDelay = 0x05,
            FirstAckRange = 0x00,
            EcnCounts = new QuicEcnCounts(1, 2, 3),
        };

        byte[] encodedAck = QuicFrameTestData.BuildAckFrame(ackFrame);
        Assert.Equal(0x03, encodedAck[0]);
        Assert.True(QuicFrameCodec.TryParseAckFrame(encodedAck, out QuicAckFrame parsedAck, out _));
        Assert.Equal(0x03, parsedAck.FrameType);
        Assert.True(parsedAck.EcnCounts.HasValue);

        Span<byte> streamDestination = stackalloc byte[32];
        Assert.True(QuicFrameCodec.TryFormatStreamFrame(0x0F, streamId: 0x04, offset: 0x10, streamData: [0xAA, 0xBB], streamDestination, out int streamBytesWritten));
        Assert.Equal(0x0F, streamDestination[0]);
        Assert.True(streamBytesWritten > 1);

        byte[] encodedMaxStreams = QuicFrameTestData.BuildMaxStreamsFrame(new QuicMaxStreamsFrame(isBidirectional: false, maximumStreams: 0x20));
        Assert.Equal(0x13, encodedMaxStreams[0]);
        Assert.True(QuicFrameCodec.TryParseMaxStreamsFrame(encodedMaxStreams, out QuicMaxStreamsFrame parsedMaxStreams, out _));
        Assert.False(parsedMaxStreams.IsBidirectional);

        byte[] encodedStreamsBlocked = QuicFrameTestData.BuildStreamsBlockedFrame(new QuicStreamsBlockedFrame(isBidirectional: true, maximumStreams: 0x33));
        Assert.Equal(0x16, encodedStreamsBlocked[0]);
        Assert.True(QuicFrameCodec.TryParseStreamsBlockedFrame(encodedStreamsBlocked, out QuicStreamsBlockedFrame parsedStreamsBlocked, out _));
        Assert.True(parsedStreamsBlocked.IsBidirectional);

        byte[] encodedConnectionClose = QuicFrameTestData.BuildConnectionCloseFrame(new QuicConnectionCloseFrame(errorCode: 0x1234, reasonPhrase: [0x6F, 0x6B]));
        Assert.Equal(0x1D, encodedConnectionClose[0]);
        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(encodedConnectionClose, out QuicConnectionCloseFrame parsedConnectionClose, out _));
        Assert.True(parsedConnectionClose.IsApplicationError);
    }
}
