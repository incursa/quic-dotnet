namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2P1-0009">Client-initiated streams MUST have even-numbered stream IDs with the least significant bit set to 0.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S2P1-0009")]
public sealed class REQ_QUIC_RFC9000_S2P1_0009
{
    [Theory]
    [InlineData(0UL)]
    [InlineData(4UL)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseStreamIdentifier_RecognizesClientInitiatedEvenStreamIds(ulong value)
    {
        byte[] encoded = QuicStreamTestData.BuildStreamIdentifier(value);

        Assert.True(QuicStreamParser.TryParseStreamIdentifier(encoded, out QuicStreamId streamId, out _));
        Assert.True(streamId.IsClientInitiated);
        Assert.False(streamId.IsServerInitiated);
        Assert.Equal(0UL, streamId.Value & 1UL);
    }
}
