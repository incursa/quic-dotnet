namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5P2-0001">A client MUST accept and process at most one Retry packet for each connection attempt.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P5P2-0001")]
public sealed class REQ_QUIC_RFC9000_S17P2P5P2_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5P2-0001">A client MUST accept and process at most one Retry packet for each connection attempt.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P5P2-0001")]
    public void ClientAcceptsAndProcessesTheFirstRetryPacketForAConnectionAttempt()
    {
        QuicConnectionRuntime runtime = QuicS17P2P5P2TestSupport.CreateBootstrappedClientRuntime();
        QuicConnectionRetryReceivedEvent retryReceivedEvent = QuicS17P2P5P2TestSupport.CreateRetryReceivedEvent(1);

        QuicConnectionTransitionResult retryResult = runtime.Transition(retryReceivedEvent, nowTicks: 1);

        Assert.True(retryResult.StateChanged);
        Assert.Contains(retryResult.Effects, effect => effect is QuicConnectionSendDatagramEffect);
        Assert.Equal(QuicConnectionPhase.Establishing, runtime.Phase);
    }
}
