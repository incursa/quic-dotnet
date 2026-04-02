namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-S7P6P2-0003")]
public sealed class REQ_QUIC_RFC9002_S7P6P2_0003
{
    public static TheoryData<PersistentCongestionGateCase> PersistentCongestionGateCases => new()
    {
        new(0, true, false, false, 12_000, 12_000),
        new(1, false, false, false, 12_000, 12_000),
        new(1, true, true, true, 2_400, 9_600),
    };

    [Theory]
    [Requirement("REQ-QUIC-RFC9002-S7P6P2-0003")]
    [MemberData(nameof(PersistentCongestionGateCases))]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Property")]
    public void TryDetectPersistentCongestion_DelaysDetectionUntilAnRttSampleExists(PersistentCongestionGateCase scenario)
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);

        QuicPersistentCongestionPacket[] packets = scenario.IncludePackets
            ? CreatePersistentCongestionPackets()
            : Array.Empty<QuicPersistentCongestionPacket>();

        Assert.Equal(
            scenario.ExpectedCallSucceeded,
            state.TryDetectPersistentCongestion(
                packets,
                firstRttSampleMicros: scenario.FirstRttSampleMicros,
                smoothedRttMicros: 1_000,
                rttVarMicros: 0,
                maxAckDelayMicros: 0,
                out bool persistentCongestionDetected));

        Assert.Equal(scenario.ExpectedPersistentCongestionDetected, persistentCongestionDetected);
        Assert.Equal(scenario.ExpectedCongestionWindowBytes, state.CongestionWindowBytes);
        Assert.Equal(scenario.ExpectedBytesInFlightBytes, state.BytesInFlightBytes);
        Assert.False(state.HasRecoveryStartTime);
    }

    private static QuicPersistentCongestionPacket[] CreatePersistentCongestionPackets()
    {
        return
        [
            new(QuicPacketNumberSpace.Initial, 2_000, 1_200, true, true, acknowledged: false, lost: true),
            new(QuicPacketNumberSpace.ApplicationData, 9_000, 1_200, true, true, acknowledged: false, lost: true),
        ];
    }

    public sealed record PersistentCongestionGateCase(
        ulong FirstRttSampleMicros,
        bool IncludePackets,
        bool ExpectedCallSucceeded,
        bool ExpectedPersistentCongestionDetected,
        ulong ExpectedCongestionWindowBytes,
        ulong ExpectedBytesInFlightBytes);
}
