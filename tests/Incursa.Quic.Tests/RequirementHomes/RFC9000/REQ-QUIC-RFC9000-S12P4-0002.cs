namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S12P4-0002">The payload of a packet that contains frames MAY contain multiple frames and multiple frame types.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S12P4-0002")]
public sealed class REQ_QUIC_RFC9000_S12P4_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParsePaddingFrame_AllowsMultipleFramesAndFrameTypesInTheSamePacketPayload()
    {
        byte[] packetPayload = [.. QuicFrameTestData.BuildPaddingFrame(), .. QuicFrameTestData.BuildPingFrame()];

        Assert.True(QuicFrameCodec.TryParsePaddingFrame(packetPayload, out int paddingBytesConsumed));
        Assert.Equal(1, paddingBytesConsumed);

        Assert.True(QuicFrameCodec.TryParsePingFrame(packetPayload[paddingBytesConsumed..], out int pingBytesConsumed));
        Assert.Equal(1, pingBytesConsumed);
        Assert.Equal(packetPayload.Length, paddingBytesConsumed + pingBytesConsumed);
    }
}
