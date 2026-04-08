namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P3-0010">An endpoint that sends a Stateless Reset in response to a packet that is 43 bytes or shorter SHOULD send a Stateless Reset that is one byte shorter than the packet it responds to.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S10P3-0010")]
public sealed class REQ_QUIC_RFC9000_S10P3_0010
{
    [Theory]
    [InlineData(43, 42)]
    [InlineData(22, 21)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryGetRecommendedDatagramLength_UsesOneByteShorterWhenPossible(int triggeringPacketLength, int expectedLength)
    {
        Assert.True(QuicStatelessReset.TryGetRecommendedDatagramLength(triggeringPacketLength, out int datagramLength));
        Assert.Equal(expectedLength, datagramLength);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryGetRecommendedDatagramLength_RejectsLengthsThatCannotBeMadeShorter()
    {
        Assert.False(QuicStatelessReset.TryGetRecommendedDatagramLength(QuicStatelessReset.MinimumDatagramLength, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryGetRecommendedDatagramLength_RejectsNonPositiveLengths()
    {
        Assert.False(QuicStatelessReset.TryGetRecommendedDatagramLength(0, out _));
        Assert.False(QuicStatelessReset.TryGetRecommendedDatagramLength(-1, out _));
    }
}
