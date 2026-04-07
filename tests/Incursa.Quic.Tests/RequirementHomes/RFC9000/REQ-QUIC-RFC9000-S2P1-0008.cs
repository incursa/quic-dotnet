namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2P1-0008">The least significant bit of a stream ID MUST identify the initiator of the stream.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S2P1-0008")]
public sealed class REQ_QUIC_RFC9000_S2P1_0008
{
    [Theory]
    [InlineData(0UL, true)]
    [InlineData(1UL, false)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseStreamIdentifier_UsesTheLeastSignificantBitToIdentifyTheInitiator(ulong value, bool isClientInitiated)
    {
        byte[] encoded = QuicStreamTestData.BuildStreamIdentifier(value);

        Assert.True(QuicStreamParser.TryParseStreamIdentifier(encoded, out QuicStreamId streamId, out _));
        Assert.Equal(isClientInitiated, streamId.IsClientInitiated);
        Assert.Equal(!isClientInitiated, streamId.IsServerInitiated);
    }
}
