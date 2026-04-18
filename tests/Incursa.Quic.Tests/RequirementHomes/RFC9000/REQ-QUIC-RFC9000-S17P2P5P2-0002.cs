namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5P2-0002">After the client has received and processed an Initial or Retry packet from the server, it MUST discard any subsequent Retry packets that it receives.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P5P2-0002")]
public sealed class REQ_QUIC_RFC9000_S17P2P5P2_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5P2-0002">After the client has received and processed an Initial or Retry packet from the server, it MUST discard any subsequent Retry packets that it receives.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P5P2-0002")]
    public void ClientDiscardsSubsequentRetryPacketsAfterProcessingTheFirstRetryPacket()
    {
        QuicConnectionRuntime runtime = QuicS17P2P5P2TestSupport.CreateBootstrappedClientRuntime();
        QuicConnectionRetryReceivedEvent retryReceivedEvent = QuicS17P2P5P2TestSupport.CreateRetryReceivedEvent(1);
        Assert.True(runtime.Transition(retryReceivedEvent, nowTicks: 1).StateChanged);

        QuicConnectionRetryReceivedEvent duplicateRetryReceivedEvent = QuicS17P2P5P2TestSupport.CreateRetryReceivedEvent(2);
        QuicConnectionTransitionResult duplicateRetryResult = runtime.Transition(duplicateRetryReceivedEvent, nowTicks: 2);

        Assert.False(duplicateRetryResult.StateChanged);
        Assert.Empty(duplicateRetryResult.Effects);
        Assert.Equal(QuicConnectionPhase.Establishing, runtime.Phase);
    }
}
