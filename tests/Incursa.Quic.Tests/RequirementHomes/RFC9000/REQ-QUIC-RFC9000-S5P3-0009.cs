namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P3-0009">In either role, an application protocol MAY identify whether the handshake has completed successfully or is still ongoing.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S5P3-0009")]
public sealed class REQ_QUIC_RFC9000_S5P3_0009
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PeerHandshakeTranscriptCompleted_TracksOngoingAndCompletedStates()
    {
        QuicConnectionRuntime runtime = CreateConnectionRuntime();

        Assert.Equal(QuicConnectionPhase.Establishing, runtime.Phase);
        Assert.False(runtime.PeerHandshakeTranscriptCompleted);
        Assert.False(runtime.TlsState.PeerHandshakeTranscriptCompleted);
        Assert.Null(runtime.TerminalState);

        QuicConnectionTransitionResult transition = runtime.Transition(
            new QuicConnectionPeerHandshakeTranscriptCompletedEvent(ObservedAtTicks: 10),
            nowTicks: 10);

        Assert.True(transition.StateChanged);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.True(runtime.PeerHandshakeTranscriptCompleted);
        Assert.Null(runtime.TerminalState);
    }

    private static QuicConnectionRuntime CreateConnectionRuntime()
    {
        return new QuicConnectionRuntime(QuicConnectionStreamStateTestHelpers.CreateState());
    }
}
