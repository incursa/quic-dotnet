namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2P1-0010">Server-initiated streams MUST have odd-numbered stream IDs with the least significant bit set to 1.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S2P1-0010")]
public sealed class REQ_QUIC_RFC9000_S2P1_0010
{
    [Theory]
    [InlineData(1UL)]
    [InlineData(5UL)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseStreamIdentifier_RecognizesServerInitiatedOddStreamIds(ulong value)
    {
        byte[] encoded = QuicStreamTestData.BuildStreamIdentifier(value);

        Assert.True(QuicStreamParser.TryParseStreamIdentifier(encoded, out QuicStreamId streamId, out _));
        Assert.True(streamId.IsServerInitiated);
        Assert.False(streamId.IsClientInitiated);
        Assert.Equal(1UL, streamId.Value & 1UL);
    }
}
