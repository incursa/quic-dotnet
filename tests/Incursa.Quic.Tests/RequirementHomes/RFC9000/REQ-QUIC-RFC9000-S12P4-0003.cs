namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S12P4-0003">The payload of a packet that contains frames MUST contain at least one frame.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S12P4-0003")]
public sealed class REQ_QUIC_RFC9000_S12P4_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S12P4-0003">The payload of a packet that contains frames MUST contain at least one frame.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S12P4-0003")]
    public void TryParseMaxDataFrame_ConsumesASingleFramePayload()
    {
        byte[] packetPayload = QuicFrameTestData.BuildMaxDataFrame(new QuicMaxDataFrame(0x1234));

        Assert.True(QuicFrameCodec.TryParseMaxDataFrame(packetPayload, out QuicMaxDataFrame parsedFrame, out int bytesConsumed));
        Assert.Equal(0x1234UL, parsedFrame.MaximumData);
        Assert.Equal(packetPayload.Length, bytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S12P4-0003">The payload of a packet that contains frames MUST contain at least one frame.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S12P4-0003")]
    public void TryParseMaxDataFrame_RejectsEmptyPacketPayloads()
    {
        Assert.False(QuicFrameCodec.TryParseMaxDataFrame(ReadOnlySpan<byte>.Empty, out _, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S12P4-0003">The payload of a packet that contains frames MUST contain at least one frame.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S12P4-0003")]
    public void TryParsePingFrame_ConsumesTheSmallestPacketPayloadThatContainsAFrame()
    {
        byte[] packetPayload = QuicFrameTestData.BuildPingFrame();

        Assert.True(QuicFrameCodec.TryParsePingFrame(packetPayload, out int bytesConsumed));
        Assert.Equal(packetPayload.Length, bytesConsumed);
    }
}
