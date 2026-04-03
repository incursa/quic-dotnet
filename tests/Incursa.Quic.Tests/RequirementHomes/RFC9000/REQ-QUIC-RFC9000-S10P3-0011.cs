namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S10P3-0011")]
public sealed class REQ_QUIC_RFC9000_S10P3_0011
{
    [Theory]
    [InlineData(100, 99)]
    [InlineData(100, 250)]
    [CoverageType(RequirementCoverageType.Positive)]
    public void CanSendStatelessReset_AllowsResponsesSmallerThanTheThreeTimesLimit(
        int triggeringPacketLength,
        int datagramLength)
    {
        Assert.True(QuicStatelessReset.CanSendStatelessReset(triggeringPacketLength, datagramLength, hasLoopPreventionState: true));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    public void CanSendStatelessReset_AllowsResponsesJustBelowTheThreeTimesLimit()
    {
        Assert.True(QuicStatelessReset.CanSendStatelessReset(100, 299, hasLoopPreventionState: true));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void CanSendStatelessReset_RejectsResponsesAtOrAboveTheThreeTimesLimit()
    {
        Assert.False(QuicStatelessReset.CanSendStatelessReset(100, 300, hasLoopPreventionState: true));
    }
}
