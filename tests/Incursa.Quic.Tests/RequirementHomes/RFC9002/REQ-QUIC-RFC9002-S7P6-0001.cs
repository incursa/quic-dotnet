namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-S7P6-0001")]
public sealed class REQ_QUIC_RFC9002_S7P6_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Positive")]
    [Trait("Category", "Negative")]
    public void TryDetectPersistentCongestion_DeclaresOnlyLongEnoughAllLostWindows()
    {
        QuicCongestionControlState shortWindowState = new();
        shortWindowState.RegisterPacketSent(12_000);

        Assert.True(shortWindowState.TryDetectPersistentCongestion(
            CreatePersistentCongestionPackets(latestLostSentAtMicros: 7_999),
            firstRttSampleMicros: 1_000,
            smoothedRttMicros: 1_000,
            rttVarMicros: 0,
            maxAckDelayMicros: 0,
            out bool shortWindowDetected));

        Assert.False(shortWindowDetected);
        Assert.NotEqual(shortWindowState.MinimumCongestionWindowBytes, shortWindowState.CongestionWindowBytes);

        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);

        Assert.True(state.TryDetectPersistentCongestion(
            CreatePersistentCongestionPackets(latestLostSentAtMicros: 8_000),
            firstRttSampleMicros: 1_000,
            smoothedRttMicros: 1_000,
            rttVarMicros: 0,
            maxAckDelayMicros: 0,
            out bool persistentCongestionDetected));

        Assert.True(persistentCongestionDetected);
        Assert.Equal(state.MinimumCongestionWindowBytes, state.CongestionWindowBytes);
    }

    private static QuicPersistentCongestionPacket[] CreatePersistentCongestionPackets(ulong latestLostSentAtMicros)
    {
        return
        [
            new(QuicPacketNumberSpace.ApplicationData, 2_000, 1_200, true, true, acknowledged: false, lost: true),
            new(QuicPacketNumberSpace.ApplicationData, latestLostSentAtMicros, 1_200, true, true, acknowledged: false, lost: true),
        ];
    }
}
