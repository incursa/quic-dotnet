namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10-0002">An endpoint MAY discard connection state if it does not have a validated path on which it can send packets.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S10-0002")]
public sealed class REQ_QUIC_RFC9000_S10_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ValidationFailureWithoutAnyValidatedPathMayDiscardConnectionState()
    {
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntime();
        QuicConnectionPathIdentity failedPath = new("203.0.113.230", RemotePort: 443);

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
        Assert.Contains(result.Effects, effect => effect is QuicConnectionDiscardConnectionStateEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ValidationFailureWithAValidatedPathRemainingDoesNotDiscardConnectionState()
    {
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(
            new("203.0.113.231", RemotePort: 443));
        QuicConnectionPathIdentity validatedPath = new("203.0.113.232", RemotePort: 443);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        Assert.False(runtime.HasValidatedPath);

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 30,
                validatedPath,
                datagram),
            nowTicks: 30).StateChanged);
        Assert.True(QuicPathMigrationRecoveryTestSupport.ValidatePath(runtime, validatedPath, observedAtTicks: 31).StateChanged);
        Assert.True(runtime.HasValidatedPath);

        QuicConnectionPathIdentity failedPath = new("203.0.113.233", RemotePort: 443);
        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPathValidationFailedEvent(
                ObservedAtTicks: 40,
                failedPath,
                IsAbandoned: true),
            nowTicks: 40);

        Assert.False(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.Equal(QuicConnectionSendingMode.Ordinary, runtime.SendingMode);
        Assert.True(runtime.CanSendOrdinaryPackets);
        Assert.True(runtime.HasValidatedPath);
        Assert.Null(runtime.TerminalState);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionDiscardConnectionStateEffect);
    }
}
