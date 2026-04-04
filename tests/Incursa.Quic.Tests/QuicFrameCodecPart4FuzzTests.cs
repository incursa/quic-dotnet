namespace Incursa.Quic.Tests;

public sealed class QuicFrameCodecPart4FuzzTests
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2-0008">QUIC MAY allow an arbitrary number of streams to operate concurrently.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2-0009">QUIC MAY allow an arbitrary amount of data to be sent on any stream, subject to flow control constraints and stream limits.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P12-0003">The Type field MUST be encoded as a variable-length integer with value 0x14.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P12-0004">The Maximum Data field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P12-0005">DATA_BLOCKED frames MUST contain the following field:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P12-0006">The Maximum Data field MUST be variable-length integer indicating the connection-level limit at which blocking occurred.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P1-0014">A sender SHOULD send a STREAM_DATA_BLOCKED or DATA_BLOCKED frame to indicate to the receiver that it has data to write but is blocked by flow control limits.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P13-0003">The Type field MUST be encoded as a variable-length integer with value 0x15.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P13-0004">The Stream ID field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P13-0005">The Maximum Stream Data field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P13-0006">STREAM_DATA_BLOCKED frames MUST contain the following fields:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P13-0007">The Stream ID field MUST be variable-length integer indicating the stream that is blocked due to flow control.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P13-0008">The Maximum Stream Data field MUST be variable-length integer indicating the offset of the stream at which the blocking occurred.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P14-0002">A STREAMS_BLOCKED frame of type 0x16 MUST be used to indicate reaching the bidirectional stream limit, and a STREAMS_BLOCKED frame of type 0x17 is used to indicate reaching the unidirectional stream limit.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P14-0004">The Type field MUST be encoded as a variable-length integer with value 0x16..0x17.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P14-0005">The Maximum Streams field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P14-0006">STREAMS_BLOCKED frames MUST contain the following field:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P14-0007">The Maximum Streams field MUST be variable-length integer indicating the maximum number of streams allowed at the time the frame was sent.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P6-0012">An endpoint that is unable to open a new stream due to the peer&apos;s limits SHOULD send a STREAMS_BLOCKED frame.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0002">The Type field MUST be encoded as a variable-length integer with value 0x18.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0003">The Sequence Number field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0004">The Retire Prior To field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0005">The Length field MUST be 8 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0006">The Connection ID field MUST be between 8 and 160 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0007">The Stateless Reset Token field MUST be 128 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0008">NEW_CONNECTION_ID frames MUST contain the following fields:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0009">The Retire Prior To field MUST be a variable-length integer indicating which connection IDs should be retired; see Section 5.1.2.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0010">The Length field MUST be 8-bit unsigned integer containing the length of the connection ID.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0012">The Connection ID field MUST be connection ID of the specified length.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0013">A 128-bit value that will be used for a stateless reset when the associated connection ID MUST be used; see Section 10.3.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0019">The value in the Retire Prior To field MUST be less than or equal to the value in the Sequence Number field.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1P2-0008">An endpoint MAY cause its peer to retire connection IDs by sending a NEW_CONNECTION_ID frame with an increased Retire Prior To field.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1P1-0005">Additional connection IDs MUST be communicated to the peer using NEW_CONNECTION_ID frames.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P16-0004">The Type field MUST be encoded as a variable-length integer with value 0x19.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P16-0005">The Sequence Number field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P16-0006">RETIRE_CONNECTION_ID frames MUST contain the following field:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1P2-0004">When the endpoint wishes to remove a connection ID from use, it MUST send a RETIRE_CONNECTION_ID frame to its peer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1P2-0005">Sending a RETIRE_CONNECTION_ID frame MUST indicate that the connection ID will not be used again and request that the peer replace it with a new connection ID using a NEW_CONNECTION_ID frame.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P17-0002">The Type field MUST be encoded as a variable-length integer with value 0x1a.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P17-0003">The Data field MUST be 64 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P17-0004">PATH_CHALLENGE frames MUST contain the following field:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P17-0005">This 8-byte field MUST contain arbitrary data.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P18-0001">The Type field MUST be encoded as a variable-length integer with value 0x1b.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P18-0002">The Data field MUST be 64 bits long.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S2-0008")]
    [Requirement("REQ-QUIC-RFC9000-S2-0009")]
    [Requirement("REQ-QUIC-RFC9000-S19P12-0003")]
    [Requirement("REQ-QUIC-RFC9000-S19P12-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P12-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P12-0006")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0014")]
    [Requirement("REQ-QUIC-RFC9000-S19P13-0003")]
    [Requirement("REQ-QUIC-RFC9000-S19P13-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P13-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P13-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P13-0007")]
    [Requirement("REQ-QUIC-RFC9000-S19P13-0008")]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0007")]
    [Requirement("REQ-QUIC-RFC9000-S4P6-0012")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0003")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0007")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0008")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0009")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0010")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0012")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0013")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0019")]
    [Requirement("REQ-QUIC-RFC9000-S5P1P2-0008")]
    [Requirement("REQ-QUIC-RFC9000-S5P1P1-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P16-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P16-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P16-0006")]
    [Requirement("REQ-QUIC-RFC9000-S5P1P2-0004")]
    [Requirement("REQ-QUIC-RFC9000-S5P1P2-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P17-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P17-0003")]
    [Requirement("REQ-QUIC-RFC9000-S19P17-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P17-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P18-0001")]
    [Requirement("REQ-QUIC-RFC9000-S19P18-0002")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void Fuzz_FrameCodecPart4_RoundTripsRepresentativeFrameShapesAndRejectsTruncation()
    {
        Random random = new(0x5160_2040);

        for (int iteration = 0; iteration < 128; iteration++)
        {
            switch (random.Next(7))
            {
                case 0:
                    RoundTripDataBlockedFrame(random);
                    break;
                case 1:
                    RoundTripStreamDataBlockedFrame(random);
                    break;
                case 2:
                    RoundTripStreamsBlockedFrame(random);
                    break;
                case 3:
                    RoundTripNewConnectionIdFrame(random);
                    break;
                case 4:
                    RoundTripRetireConnectionIdFrame(random);
                    break;
                case 5:
                    RoundTripPathFrame(random, isChallenge: true);
                    break;
                default:
                    RoundTripPathFrame(random, isChallenge: false);
                    break;
            }
        }
    }

    private static void RoundTripDataBlockedFrame(Random random)
    {
        QuicDataBlockedFrame frame = new((ulong)random.Next(0, 1 << 20));
        byte[] packet = QuicFrameTestData.BuildDataBlockedFrame(frame);

        Assert.True(QuicFrameCodec.TryParseDataBlockedFrame(packet, out QuicDataBlockedFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.MaximumData, parsed.MaximumData);
        Assert.Equal(packet.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[16];
        Assert.True(QuicFrameCodec.TryFormatDataBlockedFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(packet.Length, bytesWritten);
        Assert.True(packet.AsSpan().SequenceEqual(destination[..bytesWritten]));
        Assert.False(QuicFrameCodec.TryParseDataBlockedFrame(packet[..^1], out _, out _));
    }

    private static void RoundTripStreamDataBlockedFrame(Random random)
    {
        QuicStreamDataBlockedFrame frame = new(
            (ulong)random.Next(0, 1 << 16),
            (ulong)random.Next(0, 1 << 20));
        byte[] packet = QuicFrameTestData.BuildStreamDataBlockedFrame(frame);

        Assert.True(QuicFrameCodec.TryParseStreamDataBlockedFrame(packet, out QuicStreamDataBlockedFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.StreamId, parsed.StreamId);
        Assert.Equal(frame.MaximumStreamData, parsed.MaximumStreamData);
        Assert.Equal(packet.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicFrameCodec.TryFormatStreamDataBlockedFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(packet.Length, bytesWritten);
        Assert.True(packet.AsSpan().SequenceEqual(destination[..bytesWritten]));
        Assert.False(QuicFrameCodec.TryParseStreamDataBlockedFrame(packet[..^1], out _, out _));
    }

    private static void RoundTripStreamsBlockedFrame(Random random)
    {
        bool isBidirectional = random.Next(0, 2) == 0;
        ulong maximumStreams = random.Next(0, 16) == 0 ? 1UL << 60 : (ulong)random.Next(0, 1 << 20);
        QuicStreamsBlockedFrame frame = new(isBidirectional, maximumStreams);
        byte[] packet = QuicFrameTestData.BuildStreamsBlockedFrame(frame);

        Assert.True(QuicFrameCodec.TryParseStreamsBlockedFrame(packet, out QuicStreamsBlockedFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.IsBidirectional, parsed.IsBidirectional);
        Assert.Equal(frame.MaximumStreams, parsed.MaximumStreams);
        Assert.Equal(packet.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[16];
        Assert.True(QuicFrameCodec.TryFormatStreamsBlockedFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(packet.Length, bytesWritten);
        Assert.True(packet.AsSpan().SequenceEqual(destination[..bytesWritten]));
        Assert.False(QuicFrameCodec.TryParseStreamsBlockedFrame(packet[..^1], out _, out _));
    }

    private static void RoundTripNewConnectionIdFrame(Random random)
    {
        int connectionIdLength = random.Next(1, 21);
        byte[] connectionId = RandomBytes(random, connectionIdLength);
        byte[] statelessResetToken = RandomBytes(random, 16);
        int sequenceNumber = random.Next(0, 4096);
        ulong retirePriorTo = (ulong)random.Next(0, sequenceNumber + 1);
        QuicNewConnectionIdFrame frame = new((ulong)sequenceNumber, retirePriorTo, connectionId, statelessResetToken);
        byte[] packet = QuicFrameTestData.BuildNewConnectionIdFrame(frame);

        Assert.True(QuicFrameCodec.TryParseNewConnectionIdFrame(packet, out QuicNewConnectionIdFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.SequenceNumber, parsed.SequenceNumber);
        Assert.Equal(frame.RetirePriorTo, parsed.RetirePriorTo);
        Assert.True(connectionId.AsSpan().SequenceEqual(parsed.ConnectionId));
        Assert.True(statelessResetToken.AsSpan().SequenceEqual(parsed.StatelessResetToken));
        Assert.Equal(packet.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[64];
        Assert.True(QuicFrameCodec.TryFormatNewConnectionIdFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(packet.Length, bytesWritten);
        Assert.True(packet.AsSpan().SequenceEqual(destination[..bytesWritten]));
        Assert.False(QuicFrameCodec.TryParseNewConnectionIdFrame(packet[..^1], out _, out _));
    }

    private static void RoundTripRetireConnectionIdFrame(Random random)
    {
        QuicRetireConnectionIdFrame frame = new((ulong)random.Next(0, 4096));
        byte[] packet = QuicFrameTestData.BuildRetireConnectionIdFrame(frame);

        Assert.True(QuicFrameCodec.TryParseRetireConnectionIdFrame(packet, out QuicRetireConnectionIdFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.SequenceNumber, parsed.SequenceNumber);
        Assert.Equal(packet.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[16];
        Assert.True(QuicFrameCodec.TryFormatRetireConnectionIdFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(packet.Length, bytesWritten);
        Assert.True(packet.AsSpan().SequenceEqual(destination[..bytesWritten]));
        Assert.False(QuicFrameCodec.TryParseRetireConnectionIdFrame(packet[..^1], out _, out _));
    }

    private static void RoundTripPathFrame(Random random, bool isChallenge)
    {
        byte[] data = RandomBytes(random, 8);

        if (isChallenge)
        {
            QuicPathChallengeFrame frame = new(data);
            byte[] packet = QuicFrameTestData.BuildPathChallengeFrame(frame);

            Assert.True(QuicFrameCodec.TryParsePathChallengeFrame(packet, out QuicPathChallengeFrame parsed, out int bytesConsumed));
            Assert.True(data.AsSpan().SequenceEqual(parsed.Data));
            Assert.Equal(packet.Length, bytesConsumed);

            Span<byte> destination = stackalloc byte[16];
            Assert.True(QuicFrameCodec.TryFormatPathChallengeFrame(parsed, destination, out int bytesWritten));
            Assert.Equal(packet.Length, bytesWritten);
            Assert.True(packet.AsSpan().SequenceEqual(destination[..bytesWritten]));
            Assert.False(QuicFrameCodec.TryParsePathChallengeFrame(packet[..^1], out _, out _));
        }
        else
        {
            QuicPathResponseFrame frame = new(data);
            byte[] packet = QuicFrameTestData.BuildPathResponseFrame(frame);

            Assert.True(QuicFrameCodec.TryParsePathResponseFrame(packet, out QuicPathResponseFrame parsed, out int bytesConsumed));
            Assert.True(data.AsSpan().SequenceEqual(parsed.Data));
            Assert.Equal(packet.Length, bytesConsumed);

            Span<byte> destination = stackalloc byte[16];
            Assert.True(QuicFrameCodec.TryFormatPathResponseFrame(parsed, destination, out int bytesWritten));
            Assert.Equal(packet.Length, bytesWritten);
            Assert.True(packet.AsSpan().SequenceEqual(destination[..bytesWritten]));
            Assert.False(QuicFrameCodec.TryParsePathResponseFrame(packet[..^1], out _, out _));
        }
    }

    private static byte[] RandomBytes(Random random, int length)
    {
        byte[] data = new byte[length];
        random.NextBytes(data);
        return data;
    }
}
