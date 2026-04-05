namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S12P4-0004">An endpoint MUST treat receipt of a packet containing no frames as a connection error of type PROTOCOL_VIOLATION.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S12P4-0004")]
public sealed class REQ_QUIC_RFC9000_S12P4_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S12P4-0004">An endpoint MUST treat receipt of a packet containing no frames as a connection error of type PROTOCOL_VIOLATION.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S12P4-0004")]
    public void TryParsePaddingFrame_AcceptsTheSmallestPacketPayloadThatContainsAFrame()
    {
        byte[] packetPayload = QuicFrameTestData.BuildPaddingFrame();

        Assert.True(QuicFrameCodec.TryParsePaddingFrame(packetPayload, out int bytesConsumed));
        Assert.Equal(packetPayload.Length, bytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S12P4-0004">An endpoint MUST treat receipt of a packet containing no frames as a connection error of type PROTOCOL_VIOLATION.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S12P4-0004")]
    public void TryParsePaddingFrame_RejectsEmptyPacketPayloads()
    {
        Assert.False(QuicFrameCodec.TryParsePaddingFrame(ReadOnlySpan<byte>.Empty, out _));
        Assert.False(QuicFrameCodec.TryParsePingFrame(ReadOnlySpan<byte>.Empty, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S12P4-0004">An endpoint MUST treat receipt of a packet containing no frames as a connection error of type PROTOCOL_VIOLATION.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S12P4-0004")]
    public void TryParsePaddingFrame_ConsumesOnlyTheSingleByteAtThePacketBoundary()
    {
        Span<byte> packetPayload = stackalloc byte[1];

        Assert.True(QuicFrameCodec.TryFormatPaddingFrame(packetPayload, out int bytesWritten));
        Assert.Equal(1, bytesWritten);

        Assert.True(QuicFrameCodec.TryParsePaddingFrame(packetPayload[..bytesWritten], out int bytesConsumed));
        Assert.Equal(1, bytesConsumed);
    }
}
