namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P2P1-0006">A sender SHOULD restart its PTO timer every time an ack-eliciting packet is sent or acknowledged, or when Initial or Handshake keys are discarded.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S6P2P1-0006")]
public sealed class REQ_QUIC_RFC9002_S6P2P1_0006
{
    public static TheoryData<RestartTriggerCase> RestartTriggerCases => new()
    {
        new(true, false),
        new(false, true),
    };

    [Theory]
    [MemberData(nameof(RestartTriggerCases))]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ResetProbeTimeoutBackoffCount_RestartsPtoAfterASendOrKeyDiscard(RestartTriggerCase scenario)
    {
        Assert.Equal(0, QuicRecoveryTiming.ResetProbeTimeoutBackoffCount(
            ptoCount: 3,
            ackElicitingPacketSent: scenario.AckElicitingPacketSent,
            initialOrHandshakeKeysDiscarded: scenario.InitialOrHandshakeKeysDiscarded));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ResetProbeTimeoutBackoffCount_LeavesTheBackoffUnchangedWhenNoRestartEventOccurs()
    {
        Assert.Equal(3, QuicRecoveryTiming.ResetProbeTimeoutBackoffCount(ptoCount: 3));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ResetProbeTimeoutBackoffCount_PreservesAZeroBackoffWhenRestarted()
    {
        Assert.Equal(0, QuicRecoveryTiming.ResetProbeTimeoutBackoffCount(
            ptoCount: 0,
            ackElicitingPacketSent: true));
    }

    public sealed record RestartTriggerCase(
        bool AckElicitingPacketSent,
        bool InitialOrHandshakeKeysDiscarded);
}
