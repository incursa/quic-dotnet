namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S18P2-0018")]
public sealed class REQ_QUIC_RFC9000_S18P2_0018
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0018")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PreferredAddressPromotesAfterValidationEvenWhenDisableActiveMigrationIsSet()
    {
        QuicTransportParameters parsedTransportParameters =
            QuicS18P2DisableActiveMigrationTestSupport.ParsePeerTransportParameters(
                QuicS18P2DisableActiveMigrationTestSupport.CreatePreferredAddressPeerTransportParameters());

        using QuicConnectionRuntime runtime =
            QuicS18P2DisableActiveMigrationTestSupport.CreateRuntimeWithCommittedPeerTransportParameters(
                parsedTransportParameters);
        Assert.True(runtime.TransportFlags.HasFlag(QuicConnectionTransportState.DisableActiveMigration));

        QuicConnectionPathIdentity preferredPath =
            QuicS18P2DisableActiveMigrationTestSupport.CreatePreferredPath(parsedTransportParameters.PreferredAddress!);
        byte[] datagram = QuicS18P2DisableActiveMigrationTestSupport.CreateDatagram();

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                preferredPath,
                datagram),
            nowTicks: 20).StateChanged);

        QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            preferredPath,
            observedAtTicks: 30);

        Assert.True(validationResult.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(preferredPath, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.ActivePath!.Value.IsValidated);
        Assert.Equal(preferredPath.RemoteAddress, runtime.LastValidatedRemoteAddress);
        Assert.False(runtime.CandidatePaths.ContainsKey(preferredPath));
        Assert.Contains(validationResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promoteActivePathEffect
            && promoteActivePathEffect.PathIdentity == preferredPath);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0018")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void NonPreferredValidatedPathStillDoesNotPromoteWhenDisableActiveMigrationIsSet()
    {
        QuicTransportParameters parsedTransportParameters =
            QuicS18P2DisableActiveMigrationTestSupport.ParsePeerTransportParameters(
                QuicS18P2DisableActiveMigrationTestSupport.CreatePreferredAddressPeerTransportParameters());

        using QuicConnectionRuntime runtime =
            QuicS18P2DisableActiveMigrationTestSupport.CreateRuntimeWithCommittedPeerTransportParameters(
                parsedTransportParameters);
        Assert.True(runtime.TransportFlags.HasFlag(QuicConnectionTransportState.DisableActiveMigration));

        QuicConnectionPathIdentity nonPreferredPath =
            QuicS18P2DisableActiveMigrationTestSupport.CreateNonPreferredMigrationPath();
        byte[] datagram = QuicS18P2DisableActiveMigrationTestSupport.CreateDatagram();

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                nonPreferredPath,
                datagram),
            nowTicks: 20).StateChanged);

        QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            nonPreferredPath,
            observedAtTicks: 30);

        Assert.True(validationResult.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(QuicS18P2DisableActiveMigrationTestSupport.OriginalPath, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.CandidatePaths.TryGetValue(nonPreferredPath, out QuicConnectionCandidatePathRecord candidatePath));
        Assert.True(candidatePath.Validation.IsValidated);
        Assert.False(candidatePath.Validation.IsAbandoned);
        Assert.DoesNotContain(validationResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promoteActivePathEffect
            && promoteActivePathEffect.PathIdentity == nonPreferredPath);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0018")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void PortOnlyPreferredAddressPromotesAfterValidationEvenWhenDisableActiveMigrationIsSet()
    {
        QuicTransportParameters parsedTransportParameters =
            QuicS18P2DisableActiveMigrationTestSupport.ParsePeerTransportParameters(
                QuicS18P2DisableActiveMigrationTestSupport.CreatePortOnlyPreferredAddressPeerTransportParameters());

        using QuicConnectionRuntime runtime =
            QuicS18P2DisableActiveMigrationTestSupport.CreateRuntimeWithCommittedPeerTransportParameters(
                parsedTransportParameters);
        Assert.True(runtime.TransportFlags.HasFlag(QuicConnectionTransportState.DisableActiveMigration));

        QuicConnectionPathIdentity preferredPath =
            QuicS18P2DisableActiveMigrationTestSupport.CreatePreferredPath(parsedTransportParameters.PreferredAddress!);
        byte[] datagram = QuicS18P2DisableActiveMigrationTestSupport.CreateDatagram();

        Assert.Equal(QuicS18P2DisableActiveMigrationTestSupport.OriginalPath.RemoteAddress, preferredPath.RemoteAddress);
        Assert.NotEqual(QuicS18P2DisableActiveMigrationTestSupport.OriginalPath.RemotePort, preferredPath.RemotePort);

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                preferredPath,
                datagram),
            nowTicks: 20).StateChanged);

        QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            preferredPath,
            observedAtTicks: 30);

        Assert.True(validationResult.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(preferredPath, runtime.ActivePath!.Value.Identity);
        Assert.Equal(preferredPath.RemoteAddress, runtime.ActivePath!.Value.Identity.RemoteAddress);
        Assert.Equal(preferredPath.RemotePort, runtime.ActivePath!.Value.Identity.RemotePort);
        Assert.True(runtime.ActivePath!.Value.IsValidated);
    }
}
