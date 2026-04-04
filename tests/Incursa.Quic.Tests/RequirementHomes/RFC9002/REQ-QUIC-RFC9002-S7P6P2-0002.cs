namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P6P2-0002">Those two packets MUST be ack-eliciting.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S7P6P2-0002")]
public sealed class REQ_QUIC_RFC9002_S7P6P2_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryDetectPersistentCongestion_DetectsPersistentCongestionWhenBothDeclaredLostPacketsAreAckEliciting()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);

        Assert.True(state.TryDetectPersistentCongestion(
            [
                new(QuicPacketNumberSpace.Initial, 2_000, 1_200, ackEliciting: true, inFlight: true, acknowledged: false, lost: true),
                new(QuicPacketNumberSpace.ApplicationData, 9_000, 1_200, ackEliciting: true, inFlight: true, acknowledged: false, lost: true),
            ],
            firstRttSampleMicros: 1_000,
            smoothedRttMicros: 1_000,
            rttVarMicros: 0,
            maxAckDelayMicros: 0,
            out bool persistentCongestionDetected));

        Assert.True(persistentCongestionDetected);
    }
}
