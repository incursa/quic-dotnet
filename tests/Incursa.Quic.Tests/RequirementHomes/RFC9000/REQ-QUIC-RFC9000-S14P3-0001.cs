namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S14P3-0001")]
public sealed class REQ_QUIC_RFC9000_S14P3_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryRegisterProbeAcknowledged_RaisesTheDplpmtudMaximumPacketSize()
    {
        QuicDplpmtudState state = new();
        QuicConnectionPathIdentity path = new("203.0.113.10", "192.0.2.10", 443, 55555);

        Assert.True(state.TryTrackProbe(path, packetNumber: 10, probeSizeBytes: 1_300));
        Assert.True(state.TryRegisterProbeAcknowledged(path, packetNumber: 10));

        QuicDplpmtudPathSnapshot snapshot = state.GetPathSnapshot(path);
        Assert.Equal(1_300UL, snapshot.MaximumPacketSizeBytes);
        Assert.Equal(QuicDplpmtudProbeOutcome.Acknowledged, snapshot.LastProbeOutcome);
        Assert.Equal(10UL, snapshot.LastProbePacketNumber);
        Assert.Equal(0, snapshot.OutstandingProbeCount);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryRegisterProbeLost_TracksLossWithoutRaisingTheMaximumPacketSize()
    {
        QuicDplpmtudState state = new();
        QuicConnectionPathIdentity path = new("203.0.113.10", "192.0.2.10", 443, 55555);

        Assert.True(state.TryTrackProbe(path, packetNumber: 10, probeSizeBytes: 1_300));
        Assert.True(state.TryRegisterProbeLost(path, packetNumber: 10));

        QuicDplpmtudPathSnapshot snapshot = state.GetPathSnapshot(path);
        Assert.Equal(QuicDplpmtudState.BasePlpmtuBytes, snapshot.MaximumPacketSizeBytes);
        Assert.Equal(QuicDplpmtudProbeOutcome.Lost, snapshot.LastProbeOutcome);
        Assert.Equal(10UL, snapshot.LastProbePacketNumber);
        Assert.Equal(0, snapshot.OutstandingProbeCount);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryRegisterProbeAcknowledged_IgnoresUntrackedPacketNumbers()
    {
        QuicDplpmtudState state = new();
        QuicConnectionPathIdentity path = new("203.0.113.10", "192.0.2.10", 443, 55555);

        Assert.False(state.TryRegisterProbeAcknowledged(path, packetNumber: 10));

        QuicDplpmtudPathSnapshot snapshot = state.GetPathSnapshot(path);
        Assert.Equal(QuicDplpmtudState.BasePlpmtuBytes, snapshot.MaximumPacketSizeBytes);
        Assert.Equal(QuicDplpmtudProbeOutcome.None, snapshot.LastProbeOutcome);
    }
}
