namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S12P4-0021">An endpoint MAY treat receipt of a frame type that uses a longer encoding than necessary as a connection error of type PROTOCOL_VIOLATION.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S12P4-0021")]
public sealed class REQ_QUIC_RFC9000_S12P4_0021
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseSelectedFrames_RejectsLongerThanNecessaryFrameTypeEncodings()
    {
        byte[] nonMinimalPadding = [.. QuicVarintTestData.EncodeWithLength(0x00, 2)];
        Assert.False(QuicFrameCodec.TryParsePaddingFrame(nonMinimalPadding, out _));

        byte[] nonMinimalPing = [.. QuicVarintTestData.EncodeWithLength(0x01, 2)];
        Assert.False(QuicFrameCodec.TryParsePingFrame(nonMinimalPing, out _));

        byte[] nonMinimalAck = [.. QuicVarintTestData.EncodeWithLength(0x02, 2), 0x00, 0x00, 0x00, 0x00];
        Assert.False(QuicFrameCodec.TryParseAckFrame(nonMinimalAck, out _, out _));

        byte[] nonMinimalConnectionClose = [.. QuicVarintTestData.EncodeWithLength(0x1C, 2), 0x00, 0x00, 0x00];
        Assert.False(QuicFrameCodec.TryParseConnectionCloseFrame(nonMinimalConnectionClose, out _, out _));

        byte[] nonMinimalPathChallenge = [.. QuicVarintTestData.EncodeWithLength(0x1A, 2), 1, 2, 3, 4, 5, 6, 7, 8];
        Assert.False(QuicFrameCodec.TryParsePathChallengeFrame(nonMinimalPathChallenge, out _, out _));
    }
}
