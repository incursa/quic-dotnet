namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P6P2-0004">Persistent congestion SHOULD consider packets sent across packet number spaces.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S7P6P2-0004")]
public sealed class REQ_QUIC_RFC9002_S7P6P2_0004
{
    public static TheoryData<PersistentCongestionAcrossSpacesCase> PersistentCongestionAcrossSpacesCases => new()
    {
        new(
            [
                new(QuicPacketNumberSpace.Initial, 2_000, 1_200, true, true, acknowledged: false, lost: true),
                new(QuicPacketNumberSpace.ApplicationData, 9_000, 1_200, true, true, acknowledged: false, lost: true),
            ]),
        new(
            [
                new(QuicPacketNumberSpace.ApplicationData, 2_000, 1_200, true, true, acknowledged: false, lost: true),
                new(QuicPacketNumberSpace.Initial, 9_000, 1_200, true, true, acknowledged: false, lost: true),
            ]),
    };

    [Theory]
    [MemberData(nameof(PersistentCongestionAcrossSpacesCases))]
    [CoverageType(RequirementCoverageType.Positive)]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryDetectPersistentCongestion_ConsidersPacketsAcrossPacketNumberSpaces(
        PersistentCongestionAcrossSpacesCase scenario)
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);

        Assert.True(state.TryDetectPersistentCongestion(
            scenario.Packets,
            firstRttSampleMicros: 1_000,
            smoothedRttMicros: 1_000,
            rttVarMicros: 0,
            maxAckDelayMicros: 0,
            out bool persistentCongestionDetected));

        Assert.True(persistentCongestionDetected);
    }

    public sealed record PersistentCongestionAcrossSpacesCase(
        QuicPersistentCongestionPacket[] Packets);
}
