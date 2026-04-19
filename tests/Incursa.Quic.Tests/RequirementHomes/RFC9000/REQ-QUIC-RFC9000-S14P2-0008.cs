namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S14P2-0008">An endpoint MAY terminate the connection if an alternative path cannot be found.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S14P2-0008")]
public sealed class REQ_QUIC_RFC9000_S14P2_0008
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PathValidationFailureWithoutAnyValidatedPathDiscardsTheConnection()
    {
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntime();
        QuicConnectionPathIdentity failedPath = new("203.0.113.208", RemotePort: 443);

        Assert.False(runtime.HasValidatedPath);
        Assert.Null(runtime.ActivePath);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPathValidationFailedEvent(
                ObservedAtTicks: 20,
                failedPath,
                IsAbandoned: true),
            nowTicks: 20);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Discarded, runtime.Phase);
        Assert.Equal(QuicConnectionSendingMode.None, runtime.SendingMode);
        Assert.False(runtime.CanSendOrdinaryPackets);
        Assert.True(runtime.TerminalState.HasValue);
        Assert.Equal(QuicConnectionPhase.Discarded, runtime.TerminalState.Value.Phase);
        Assert.Equal(QuicConnectionCloseOrigin.Remote, runtime.TerminalState.Value.Origin);
        Assert.Contains(result.Effects, effect => effect is QuicConnectionDiscardConnectionStateEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void PathValidationFailureDoesNotDiscardWhileAValidatedPathRemainsAvailable()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        QuicConnectionPathIdentity failedPath = new("203.0.113.210", RemotePort: 443);

        Assert.True(runtime.HasValidatedPath);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.True(runtime.ActivePath.HasValue);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPathValidationFailedEvent(
                ObservedAtTicks: 30,
                failedPath,
                IsAbandoned: true),
            nowTicks: 30);

        Assert.False(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.Equal(QuicConnectionSendingMode.Ordinary, runtime.SendingMode);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Null(runtime.TerminalState);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionDiscardConnectionStateEffect);
    }
}
