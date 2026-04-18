namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P15-0019")]
public sealed class REQ_QUIC_RFC9000_S19P15_0019
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0019">The value in the Retire Prior To field MUST be less than or equal to the value in the Sequence Number field.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0020">Receiving a value in the Retire Prior To field that is greater than that in the Sequence Number field MUST be treated as a connection error of type FRAME_ENCODING_ERROR.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P15-0019")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0020")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseNewConnectionIdFrame_RejectsRetirePriorToGreaterThanSequenceNumber()
    {
        byte[] connectionId = [0x10, 0x11];
        byte[] statelessResetToken = [
            0x20, 0x21, 0x22, 0x23,
            0x24, 0x25, 0x26, 0x27,
            0x28, 0x29, 0x2A, 0x2B,
            0x2C, 0x2D, 0x2E, 0x2F];
        QuicNewConnectionIdFrame frame = new(0x03, 0x04, connectionId, statelessResetToken);
        byte[] encoded = QuicFrameTestData.BuildNewConnectionIdFrame(frame);

        Assert.False(QuicFrameCodec.TryParseNewConnectionIdFrame(encoded, out _, out _));
        Assert.False(QuicFrameCodec.TryFormatNewConnectionIdFrame(frame, stackalloc byte[64], out _));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0019">The value in the Retire Prior To field MUST be less than or equal to the value in the Sequence Number field.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0020">Receiving a value in the Retire Prior To field that is greater than that in the Sequence Number field MUST be treated as a connection error of type FRAME_ENCODING_ERROR.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P15-0019")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0020")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseNewConnectionIdFrame_ParsesRetirePriorToLessThanSequenceNumber()
    {
        byte[] connectionId = [0x20, 0x21, 0x22];
        byte[] statelessResetToken = [
            0x50, 0x51, 0x52, 0x53,
            0x54, 0x55, 0x56, 0x57,
            0x58, 0x59, 0x5A, 0x5B,
            0x5C, 0x5D, 0x5E, 0x5F];

        QuicNewConnectionIdFrame frame = new(0x05, 0x04, connectionId, statelessResetToken);
        byte[] encoded = QuicFrameTestData.BuildNewConnectionIdFrame(frame);

        Assert.True(QuicFrameCodec.TryParseNewConnectionIdFrame(encoded, out QuicNewConnectionIdFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.SequenceNumber, parsed.SequenceNumber);
        Assert.Equal(frame.RetirePriorTo, parsed.RetirePriorTo);
        Assert.True(connectionId.AsSpan().SequenceEqual(parsed.ConnectionId));
        Assert.True(statelessResetToken.AsSpan().SequenceEqual(parsed.StatelessResetToken));
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[64];
        Assert.True(QuicFrameCodec.TryFormatNewConnectionIdFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0019">The value in the Retire Prior To field MUST be less than or equal to the value in the Sequence Number field.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0020">Receiving a value in the Retire Prior To field that is greater than that in the Sequence Number field MUST be treated as a connection error of type FRAME_ENCODING_ERROR.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P15-0019")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0020")]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryParseNewConnectionIdFrame_AcceptsRetirePriorToEqualToSequenceNumber()
    {
        byte[] connectionId = [0x30, 0x31, 0x32];
        byte[] statelessResetToken = [
            0x40, 0x41, 0x42, 0x43,
            0x44, 0x45, 0x46, 0x47,
            0x48, 0x49, 0x4A, 0x4B,
            0x4C, 0x4D, 0x4E, 0x4F];

        QuicNewConnectionIdFrame frame = new(0x05, 0x05, connectionId, statelessResetToken);
        byte[] encoded = QuicFrameTestData.BuildNewConnectionIdFrame(frame);

        Assert.True(QuicFrameCodec.TryParseNewConnectionIdFrame(encoded, out QuicNewConnectionIdFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.SequenceNumber, parsed.SequenceNumber);
        Assert.Equal(frame.RetirePriorTo, parsed.RetirePriorTo);
        Assert.True(connectionId.AsSpan().SequenceEqual(parsed.ConnectionId));
        Assert.True(statelessResetToken.AsSpan().SequenceEqual(parsed.StatelessResetToken));
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[64];
        Assert.True(QuicFrameCodec.TryFormatNewConnectionIdFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }
}
