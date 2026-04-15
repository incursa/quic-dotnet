namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P3-0031">No special support MUST be used for detecting reordered and duplicated NEW_TOKEN frames other than a direct comparison of the frame contents.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P3-0031")]
public sealed class REQ_QUIC_RFC9000_S13P3_0031
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ParsedDuplicateNewTokenFramesCompareEqualByTokenBytes()
    {
        byte[] firstToken =
        [
            0x10, 0x20, 0x30, 0x40,
        ];

        byte[] duplicateToken =
        [
            0x10, 0x20, 0x30, 0x40,
        ];

        byte[] firstEncoded = QuicFrameTestData.BuildNewTokenFrame(new(firstToken));
        byte[] duplicateEncoded = QuicFrameTestData.BuildNewTokenFrame(new(duplicateToken));

        Assert.True(QuicFrameCodec.TryParseNewTokenFrame(firstEncoded, out QuicNewTokenFrame firstParsed, out int firstBytesConsumed));
        Assert.True(QuicFrameCodec.TryParseNewTokenFrame(duplicateEncoded, out QuicNewTokenFrame duplicateParsed, out int duplicateBytesConsumed));

        Assert.Equal(firstEncoded.Length, firstBytesConsumed);
        Assert.Equal(duplicateEncoded.Length, duplicateBytesConsumed);
        Assert.True(firstParsed.Token.SequenceEqual(duplicateParsed.Token));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ParsedNewTokenFramesWithDifferentTokenBytesDoNotCompareEqualByTokenBytes()
    {
        byte[] firstToken =
        [
            0x10, 0x20, 0x30, 0x40,
        ];

        byte[] reorderedToken =
        [
            0x40, 0x30, 0x20, 0x10,
        ];

        byte[] firstEncoded = QuicFrameTestData.BuildNewTokenFrame(new(firstToken));
        byte[] reorderedEncoded = QuicFrameTestData.BuildNewTokenFrame(new(reorderedToken));

        Assert.True(QuicFrameCodec.TryParseNewTokenFrame(firstEncoded, out QuicNewTokenFrame firstParsed, out int firstBytesConsumed));
        Assert.True(QuicFrameCodec.TryParseNewTokenFrame(reorderedEncoded, out QuicNewTokenFrame reorderedParsed, out int reorderedBytesConsumed));

        Assert.Equal(firstEncoded.Length, firstBytesConsumed);
        Assert.Equal(reorderedEncoded.Length, reorderedBytesConsumed);
        Assert.False(firstParsed.Token.SequenceEqual(reorderedParsed.Token));
    }
}
