namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P1-0003">Once the packet has been fully processed, a receiver MUST acknowledge receipt by sending one or more ACK frames containing the packet number of the received packet.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P1-0003")]
public sealed class REQ_QUIC_RFC9000_S13P1_0003
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P1-0003")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryBuildAckFrame_EmitsAnAckFrameForAProcessedPacketNumber()
    {
        QuicAckGenerationState tracker = new();

        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            4,
            ackEliciting: true,
            receivedAtMicros: 1_000);

        Assert.True(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_500,
            out QuicAckFrame frame));
        Assert.Equal(4UL, frame.LargestAcknowledged);
        Assert.Equal(0UL, frame.FirstAckRange);
        Assert.Empty(frame.AdditionalRanges);

        Span<byte> encoded = stackalloc byte[32];
        Assert.True(QuicFrameCodec.TryFormatAckFrame(frame, encoded, out int bytesWritten));
        Assert.True(QuicFrameCodec.TryParseAckFrame(encoded[..bytesWritten], out QuicAckFrame parsedFrame, out int bytesConsumed));
        Assert.Equal(bytesWritten, bytesConsumed);
        Assert.Equal(frame.LargestAcknowledged, parsedFrame.LargestAcknowledged);
        Assert.Equal(frame.FirstAckRange, parsedFrame.FirstAckRange);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P1-0003")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryBuildAckFrame_RejectsAnEmptyAcknowledgmentSet()
    {
        QuicAckGenerationState tracker = new();

        Assert.False(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_500,
            out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P1-0003")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryBuildAckFrame_PreservesPacketNumberZeroAtTheAckBoundary()
    {
        QuicAckGenerationState tracker = new();

        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            0,
            ackEliciting: true,
            receivedAtMicros: 2_000);

        Assert.True(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 2_000,
            out QuicAckFrame frame));
        Assert.Equal(0UL, frame.LargestAcknowledged);
        Assert.Equal(0UL, frame.FirstAckRange);
        Assert.Empty(frame.AdditionalRanges);
        Assert.Equal(0UL, frame.AckDelay);

        Span<byte> encoded = stackalloc byte[32];
        Assert.True(QuicFrameCodec.TryFormatAckFrame(frame, encoded, out int bytesWritten));
        Assert.True(QuicFrameCodec.TryParseAckFrame(encoded[..bytesWritten], out QuicAckFrame parsedFrame, out int bytesConsumed));
        Assert.Equal(bytesWritten, bytesConsumed);
        Assert.Equal(0UL, parsedFrame.LargestAcknowledged);
    }
}
