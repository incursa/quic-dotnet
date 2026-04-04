namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P1P1-0001">An endpoint MAY send a PING or another ack-eliciting frame to test the connection for liveness if the peer could time out soon.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S10P1P1-0001")]
public sealed class REQ_QUIC_RFC9000_S10P1P1_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatPingFrame_ProducesAnAckElicitingLivenessProbe()
    {
        Span<byte> destination = stackalloc byte[1];

        Assert.True(QuicFrameCodec.TryFormatPingFrame(destination, out int bytesWritten));
        Assert.Equal(1, bytesWritten);
        Assert.Equal((byte)0x01, destination[0]);
        Assert.True(QuicFrameCodec.IsAckElicitingFrameType(0x01));

        Assert.True(QuicFrameCodec.TryParsePingFrame(destination, out int bytesConsumed));
        Assert.Equal(1, bytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryFormatPingFrame_RejectsAZeroLengthDestination()
    {
        Assert.False(QuicFrameCodec.TryFormatPingFrame(stackalloc byte[0], out _));
    }
}
