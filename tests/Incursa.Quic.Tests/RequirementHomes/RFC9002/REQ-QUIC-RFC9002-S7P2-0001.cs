namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-S7P2-0001")]
public sealed class REQ_QUIC_RFC9002_S7P2_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void Constructor_SeedsTheDefaultConnectionInSlowStart()
    {
        QuicCongestionControlState state = new();

        Assert.Equal((ulong)QuicVersionNegotiation.Version1MinimumDatagramPayloadSize, state.MaxDatagramSizeBytes);
        Assert.Equal(12_000UL, state.CongestionWindowBytes);
        Assert.Equal(2_400UL, state.MinimumCongestionWindowBytes);
        Assert.Equal(ulong.MaxValue, state.SlowStartThresholdBytes);
        Assert.Equal(0UL, state.BytesInFlightBytes);
        Assert.True(state.IsInSlowStart);
        Assert.False(state.IsInCongestionAvoidance);
    }

    [Theory]
    [InlineData(QuicVersionNegotiation.Version1MinimumDatagramPayloadSize, 12_000UL)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Property")]
    public void Constructor_HonorsTheRFCMinimumDatagramSize(
        ulong maxDatagramSizeBytes,
        ulong expectedCongestionWindowBytes)
    {
        QuicCongestionControlState state = new(maxDatagramSizeBytes);

        Assert.Equal(maxDatagramSizeBytes, state.MaxDatagramSizeBytes);
        Assert.Equal(expectedCongestionWindowBytes, state.CongestionWindowBytes);
        Assert.Equal(2 * maxDatagramSizeBytes, state.MinimumCongestionWindowBytes);
        Assert.Equal(ulong.MaxValue, state.SlowStartThresholdBytes);
        Assert.True(state.IsInSlowStart);
        Assert.False(state.IsInCongestionAvoidance);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void Constructor_RejectsZeroDatagramSizes()
    {
        ArgumentOutOfRangeException exception = Assert.Throws<ArgumentOutOfRangeException>(() => new QuicCongestionControlState(0));
        Assert.Equal("maxDatagramSizeBytes", exception.ParamName);
    }
}
