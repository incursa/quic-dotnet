namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P2P4-0005">An endpoint SHOULD include new data in packets that are sent on PTO expiration.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S6P2P4-0005")]
public sealed class REQ_QUIC_RFC9002_S6P2P4_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatStreamFrame_RoundTripsNewApplicationData()
    {
        byte[] streamData = [0x40, 0x41, 0x42];
        byte[] packet = QuicStreamTestData.BuildStreamFrame(
            frameType: 0x0F,
            streamId: 0x06,
            streamData,
            offset: 0);

        Assert.True(QuicStreamParser.TryParseStreamFrame(packet, out QuicStreamFrame frame));
        Assert.True(frame.HasOffset);
        Assert.True(frame.HasLength);
        Assert.Equal(0UL, frame.Offset);
        Assert.Equal((ulong)streamData.Length, frame.Length);
        Assert.True(streamData.AsSpan().SequenceEqual(frame.StreamData));

        Span<byte> destination = stackalloc byte[64];
        Assert.True(QuicFrameCodec.TryFormatStreamFrame(
            frame.FrameType,
            frame.StreamId.Value,
            frame.Offset,
            frame.StreamData,
            destination,
            out int bytesWritten));
        Assert.Equal(packet.Length, bytesWritten);
        Assert.True(packet.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }
}
