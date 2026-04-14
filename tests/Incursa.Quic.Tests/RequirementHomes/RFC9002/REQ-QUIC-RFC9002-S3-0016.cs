namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S3-0016">Packets containing PADDING frames MUST contribute toward bytes in flight.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S3-0016")]
public sealed class REQ_QUIC_RFC9002_S3_0016
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RegisterPacketSent_CountsPaddingOnlyPacketsTowardBytesInFlight()
    {
        Span<byte> paddingFrame = stackalloc byte[1];

        Assert.True(QuicFrameCodec.TryFormatPaddingFrame(paddingFrame, out int bytesWritten));
        Assert.Equal((byte)0x00, paddingFrame[0]);
        Assert.False(QuicFrameCodec.IsAckElicitingFrameType(paddingFrame[0]));

        QuicCongestionControlState state = new();
        state.RegisterPacketSent((ulong)bytesWritten, isAckOnlyPacket: false);

        Assert.Equal((ulong)bytesWritten, state.BytesInFlightBytes);
    }
}
