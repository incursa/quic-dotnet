namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1P1-0001">Each connection ID MUST have an associated sequence number to assist in detecting when NEW_CONNECTION_ID or RETIRE_CONNECTION_ID frames refer to the same value.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S5P1P1-0001")]
public sealed class REQ_QUIC_RFC9000_S5P1P1_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1P1-0001">Each connection ID MUST have an associated sequence number to assist in detecting when NEW_CONNECTION_ID or RETIRE_CONNECTION_ID frames refer to the same value.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S5P1P1-0001")]
    public void TryParseNewConnectionIdFrame_ExposesTheSequenceNumberOnTheWire()
    {
        byte[] connectionId = [0x10, 0x11, 0x12, 0x13];
        byte[] statelessResetToken = [
            0x20, 0x21, 0x22, 0x23,
            0x24, 0x25, 0x26, 0x27,
            0x28, 0x29, 0x2A, 0x2B,
            0x2C, 0x2D, 0x2E, 0x2F];

        QuicNewConnectionIdFrame frame = new(0x06, 0x04, connectionId, statelessResetToken);
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

        QuicRetireConnectionIdFrame retireFrame = new(frame.SequenceNumber);
        byte[] retireEncoded = QuicFrameTestData.BuildRetireConnectionIdFrame(retireFrame);

        Assert.True(QuicFrameCodec.TryParseRetireConnectionIdFrame(retireEncoded, out QuicRetireConnectionIdFrame parsedRetire, out int retireBytesConsumed));
        Assert.Equal(frame.SequenceNumber, parsedRetire.SequenceNumber);
        Assert.Equal(retireEncoded.Length, retireBytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1P1-0001">Each connection ID MUST have an associated sequence number to assist in detecting when NEW_CONNECTION_ID or RETIRE_CONNECTION_ID frames refer to the same value.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S5P1P1-0001")]
    public void TryParseNewConnectionIdFrame_RejectsTruncatedInput()
    {
        byte[] connectionId = [0x10];
        byte[] statelessResetToken = [
            0x20, 0x21, 0x22, 0x23,
            0x24, 0x25, 0x26, 0x27,
            0x28, 0x29, 0x2A, 0x2B,
            0x2C, 0x2D, 0x2E, 0x2F];
        QuicNewConnectionIdFrame frame = new(0x06, 0x04, connectionId, statelessResetToken);
        byte[] encoded = QuicFrameTestData.BuildNewConnectionIdFrame(frame);

        Assert.False(QuicFrameCodec.TryParseNewConnectionIdFrame(encoded[..^1], out _, out _));
        Assert.False(QuicFrameCodec.TryParseRetireConnectionIdFrame([0x19], out _, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1P1-0001">Each connection ID MUST have an associated sequence number to assist in detecting when NEW_CONNECTION_ID or RETIRE_CONNECTION_ID frames refer to the same value.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S5P1P1-0001")]
    public void TryParseNewConnectionIdFrame_AllowsSequenceNumberZero()
    {
        byte[] connectionId = [0x10];
        byte[] statelessResetToken = [
            0x30, 0x31, 0x32, 0x33,
            0x34, 0x35, 0x36, 0x37,
            0x38, 0x39, 0x3A, 0x3B,
            0x3C, 0x3D, 0x3E, 0x3F];

        QuicNewConnectionIdFrame frame = new(0, 0, connectionId, statelessResetToken);
        byte[] encoded = QuicFrameTestData.BuildNewConnectionIdFrame(frame);

        Assert.True(QuicFrameCodec.TryParseNewConnectionIdFrame(encoded, out QuicNewConnectionIdFrame parsed, out int bytesConsumed));
        Assert.Equal(0UL, parsed.SequenceNumber);
        Assert.Equal(0UL, parsed.RetirePriorTo);
        Assert.True(connectionId.AsSpan().SequenceEqual(parsed.ConnectionId));
        Assert.True(statelessResetToken.AsSpan().SequenceEqual(parsed.StatelessResetToken));
        Assert.Equal(encoded.Length, bytesConsumed);
    }
}
