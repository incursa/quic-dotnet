namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2P1-0011">The second least significant bit of a stream ID MUST distinguish bidirectional streams from unidirectional streams, with 0 indicating bidirectional and 1 indicating unidirectional.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S2P1-0011")]
public sealed class REQ_QUIC_RFC9000_S2P1_0011
{
    [Theory]
    [InlineData(0UL, QuicStreamType.ClientInitiatedBidirectional, true)]
    [InlineData(1UL, QuicStreamType.ServerInitiatedBidirectional, true)]
    [InlineData(2UL, QuicStreamType.ClientInitiatedUnidirectional, false)]
    [InlineData(3UL, QuicStreamType.ServerInitiatedUnidirectional, false)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseStreamIdentifier_UsesTheSecondLeastSignificantBitToDistinguishDirection(
        ulong value,
        QuicStreamType expectedStreamType,
        bool expectedBidirectional)
    {
        byte[] encoded = QuicStreamTestData.BuildStreamIdentifier(value);

        Assert.True(QuicStreamParser.TryParseStreamIdentifier(encoded, out QuicStreamId streamId, out _));
        Assert.Equal(expectedStreamType, streamId.StreamType);
        Assert.Equal(expectedBidirectional, streamId.IsBidirectional);
        Assert.Equal(!expectedBidirectional, streamId.IsUnidirectional);
    }
}
