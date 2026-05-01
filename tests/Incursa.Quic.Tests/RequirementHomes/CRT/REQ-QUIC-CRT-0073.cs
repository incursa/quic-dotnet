namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0073")]
public sealed class REQ_QUIC_CRT_0073
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ValidationFailureWithoutAnyValidatedPathSurfacesDiagnosticsAndDiscard()
    {
        QuicRecordingDiagnosticsSink diagnosticsSink = new();
        QuicConnectionPathIdentity activePath = new("203.0.113.174", RemotePort: 443);
        QuicConnectionPathIdentity failedPath = new("203.0.113.175", RemotePort: 443);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(
            activePath,
            diagnosticsSink);

        Assert.False(runtime.HasValidatedPath);

        QuicConnectionTransitionResult failureResult = runtime.Transition(
            new QuicConnectionPathValidationFailedEvent(
                ObservedAtTicks: 20,
                failedPath,
                IsAbandoned: true),
            nowTicks: 20);

        Assert.True(failureResult.StateChanged);
        Assert.Equal(QuicConnectionPhase.Discarded, runtime.Phase);
        Assert.Equal(QuicConnectionSendingMode.None, runtime.SendingMode);
        Assert.Contains(failureResult.Effects, effect => effect is QuicConnectionDiscardConnectionStateEffect);
        Assert.Contains(
            diagnosticsSink.Events,
            diagnosticEvent => diagnosticEvent.Kind == QuicDiagnosticKind.PathValidationFailedNoValidatedPathsRemain
                && diagnosticEvent.Message.Contains(failedPath.RemoteAddress, StringComparison.Ordinal));
    }
}
