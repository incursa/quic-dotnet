namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P21-0002">An endpoint therefore needs to understand the syntax of all frames before it MAY successfully process a packet.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S19P21-0002")]
public sealed class REQ_QUIC_RFC9000_S19P21_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P21-0002">An endpoint therefore needs to understand the syntax of all frames before it MAY successfully process a packet.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P21-0002")]
    public void TryParseTypeOnlyFrames_ConsumesOnlyTheDeclaredFrameSyntax()
    {
        byte[] packet =
        [
            0x00,
            0x01,
            0x1E,
            0xAA,
        ];

        Assert.True(QuicFrameCodec.TryParsePaddingFrame(packet, out int paddingConsumed));
        Assert.Equal(1, paddingConsumed);

        Assert.True(QuicFrameCodec.TryParsePingFrame(packet[paddingConsumed..], out int pingConsumed));
        Assert.Equal(1, pingConsumed);

        Assert.True(QuicFrameCodec.TryParseHandshakeDoneFrame(packet[(paddingConsumed + pingConsumed)..], out _, out int handshakeConsumed));
        Assert.Equal(1, handshakeConsumed);

        Assert.Equal(3, paddingConsumed + pingConsumed + handshakeConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P21-0002">An endpoint therefore needs to understand the syntax of all frames before it MAY successfully process a packet.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P21-0002")]
    public void TryParseTypeOnlyFrames_RejectsEmptyAndMismatchedTypes()
    {
        Assert.False(QuicFrameCodec.TryParsePaddingFrame([], out _));
        Assert.False(QuicFrameCodec.TryParsePingFrame([0x00], out _));
        Assert.False(QuicFrameCodec.TryParseHandshakeDoneFrame([0x40, 0x1E], out _, out _));
    }
}
