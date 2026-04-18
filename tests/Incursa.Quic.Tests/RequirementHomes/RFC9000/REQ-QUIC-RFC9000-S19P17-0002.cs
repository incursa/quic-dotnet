namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P17-0002")]
public sealed class REQ_QUIC_RFC9000_S19P17_0002
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P17-0002">The Type field MUST be encoded as a variable-length integer with value 0x1a.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P17-0003">The Data field MUST be 64 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P17-0004">PATH_CHALLENGE frames MUST contain the following field:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P17-0005">This 8-byte field MUST contain arbitrary data.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P17-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P17-0003")]
    [Requirement("REQ-QUIC-RFC9000-S19P17-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P17-0005")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParsePathChallengeFrame_ParsesAndFormatsTheEightBytePayload()
    {
        byte[] data = [
            0xA0, 0xA1, 0xA2, 0xA3,
            0xA4, 0xA5, 0xA6, 0xA7];

        QuicPathChallengeFrame frame = new(data);
        byte[] encoded = QuicFrameTestData.BuildPathChallengeFrame(frame);

        Assert.True(QuicFrameCodec.TryParsePathChallengeFrame(encoded, out QuicPathChallengeFrame parsed, out int bytesConsumed));
        Assert.True(data.AsSpan().SequenceEqual(parsed.Data));
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[16];
        Assert.True(QuicFrameCodec.TryFormatPathChallengeFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P17-0002">The Type field MUST be encoded as a variable-length integer with value 0x1a.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P17-0002")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryFormatPathChallengeFrame_UsesTheMinimumNineByteBoundary()
    {
        byte[] data = [
            0xB0, 0xB1, 0xB2, 0xB3,
            0xB4, 0xB5, 0xB6, 0xB7];

        QuicPathChallengeFrame frame = new(data);
        Span<byte> destination = stackalloc byte[9];

        Assert.True(QuicFrameCodec.TryFormatPathChallengeFrame(frame, destination, out int bytesWritten));
        Assert.Equal(9, bytesWritten);
        Assert.Equal(0x1A, destination[0]);

        Assert.True(QuicFrameCodec.TryParsePathChallengeFrame(destination[..bytesWritten], out QuicPathChallengeFrame parsed, out int bytesConsumed));
        Assert.Equal(bytesWritten, bytesConsumed);
        Assert.True(data.AsSpan().SequenceEqual(parsed.Data));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void Fuzz_PathChallengeFrame_RoundTripsRepresentativeShapesAndRejectsTruncation()
    {
        QuicFrameCodecPart4FuzzSupport.FuzzPathChallengeFrame();
    }
}
