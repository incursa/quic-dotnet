// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P14-0002")]
public sealed class REQ_QUIC_RFC9000_S19P14_0002
{
    [Theory]
    [InlineData(true, 0x16UL)]
    [InlineData(false, 0x17UL)]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseStreamsBlockedFrame_MapsType16And17ToStreamDirection(
        bool isBidirectional,
        ulong expectedFrameType)
    {
        byte[] encoded = QuicS19P14StreamsBlockedFrameTestSupport.BuildStreamsBlockedFrame(
            isBidirectional,
            maximumStreams: 7);

        Assert.True(QuicVariableLengthInteger.TryParse(encoded, out ulong frameType, out int bytesConsumed));
        Assert.Equal(expectedFrameType, frameType);
        Assert.Equal(1, bytesConsumed);
        QuicS19P14StreamsBlockedFrameTestSupport.AssertParses(encoded, isBidirectional, expectedMaximumStreams: 7);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ProtectedStreamsBlockedFrame_AcceptsType16And17AsAckElicitingAdvisories(bool isBidirectional)
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        byte[] encoded = QuicS19P14StreamsBlockedFrameTestSupport.BuildStreamsBlockedFrame(
            isBidirectional,
            maximumStreams: 7);

        QuicConnectionTransitionResult result = QuicS19P7NewTokenFrameTestSupport.ReceiveProtectedApplicationPacket(
            runtime,
            encoded,
            observedAtTicks: 20);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.Null(runtime.TerminalState);
    }

    [Theory]
    [InlineData(0x15)]
    [InlineData(0x18)]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0002")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseStreamsBlockedFrame_RejectsNonStreamsBlockedFrameTypes(byte frameType)
    {
        byte[] encoded = QuicS19P14StreamsBlockedFrameTestSupport.BuildStreamsBlockedFrameWithEncodedType([frameType]);

        QuicS19P14StreamsBlockedFrameTestSupport.AssertRejects(encoded);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0002")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseStreamsBlockedFrame_RejectsNonMinimalDirectionTypeEncodings()
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

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0027">QUIC MUST allow an arbitrary number of streams to operate concurrently, subject to flow control constraints and stream limits.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P14-0002">A STREAMS_BLOCKED frame of type 0x16 MUST be used to indicate reaching the bidirectional stream limit, and a STREAMS_BLOCKED frame of type 0x17 is used to indicate reaching the unidirectional stream limit.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P14-0004">The Type field MUST be encoded as a variable-length integer with value 0x16..0x17.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P14-0005">The Maximum Streams field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P14-0006">STREAMS_BLOCKED frames MUST contain the following field:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P14-0007">The Maximum Streams field MUST be variable-length integer indicating the maximum number of streams allowed at the time the frame was sent.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0203">An endpoint that is unable to open a new stream due to the peer&apos;s limits SHOULD send a STREAMS_BLOCKED frame.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-0027")]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0007")]
    [Requirement("REQ-QUIC-RFC9000-0203")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseStreamsBlockedFrame_ParsesAndFormatsBidirectionalAndUnidirectionalVariants(bool isBidirectional)
    {
        QuicStreamsBlockedFrame frame = new(isBidirectional, 0x1234);
        byte[] encoded = QuicFrameTestData.BuildStreamsBlockedFrame(frame);

        Assert.True(QuicFrameCodec.TryParseStreamsBlockedFrame(encoded, out QuicStreamsBlockedFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.IsBidirectional, parsed.IsBidirectional);
        Assert.Equal(frame.MaximumStreams, parsed.MaximumStreams);
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[16];
        Assert.True(QuicFrameCodec.TryFormatStreamsBlockedFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0027">QUIC MUST allow an arbitrary number of streams to operate concurrently, subject to flow control constraints and stream limits.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P14-0002">A STREAMS_BLOCKED frame of type 0x16 MUST be used to indicate reaching the bidirectional stream limit, and a STREAMS_BLOCKED frame of type 0x17 is used to indicate reaching the unidirectional stream limit.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P14-0004">The Type field MUST be encoded as a variable-length integer with value 0x16..0x17.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P14-0005">The Maximum Streams field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P14-0006">STREAMS_BLOCKED frames MUST contain the following field:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P14-0007">The Maximum Streams field MUST be variable-length integer indicating the maximum number of streams allowed at the time the frame was sent.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P14-0008">This value MUST NOT exceed 260, as it is not possible to encode stream IDs larger than 262-1.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-0027")]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0007")]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0008")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseStreamsBlockedFrame_AcceptsValueAtTheEncodingLimit(bool isBidirectional)
    {
        ulong limit = 1UL << 60;
        QuicStreamsBlockedFrame frame = new(isBidirectional, limit);
        byte[] encoded = QuicFrameTestData.BuildStreamsBlockedFrame(frame);

        Assert.True(QuicFrameCodec.TryParseStreamsBlockedFrame(encoded, out QuicStreamsBlockedFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.IsBidirectional, parsed.IsBidirectional);
        Assert.Equal(limit, parsed.MaximumStreams);
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[16];
        Assert.True(QuicFrameCodec.TryFormatStreamsBlockedFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void Fuzz_StreamsBlockedFrame_RoundTripsRepresentativeShapesAndRejectsTruncation()
    {
        QuicFrameCodecPart4FuzzSupport.FuzzStreamsBlockedFrame();
    }
}
