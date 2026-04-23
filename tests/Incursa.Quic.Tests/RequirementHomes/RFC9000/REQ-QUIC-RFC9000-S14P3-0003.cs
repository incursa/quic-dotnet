namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S14P3-0003")]
public sealed class REQ_QUIC_RFC9000_S14P3_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void InitialPathStateUsesTheQuicMinimumAsBasePlpmtu()
    {
        QuicDplpmtudState state = new();
        QuicConnectionPathIdentity path = new("203.0.113.12", "192.0.2.10", 443, 55555);

        QuicDplpmtudPathSnapshot snapshot = state.GetPathSnapshot(path);

        Assert.Equal(QuicConnectionPathMaximumDatagramSizeState.MinimumAllowedMaximumDatagramSizeBytes, snapshot.BasePlpmtuBytes);
        Assert.Equal(snapshot.BasePlpmtuBytes, snapshot.MaximumPacketSizeBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ConstructorRejectsABasePlpmtuBelowTheQuicMinimum()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new QuicDplpmtudState(QuicDplpmtudState.BasePlpmtuBytes - 1));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ConstructorRejectsABasePlpmtuAboveTheQuicMinimum()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new QuicDplpmtudState(QuicDplpmtudState.BasePlpmtuBytes + 1));
    }
}
