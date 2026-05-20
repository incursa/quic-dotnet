namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S18P2-0017")]
public sealed class REQ_QUIC_RFC9000_S18P2_0017
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0017")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ValidatedNewLocalAddressCandidateDoesNotPromoteWhenDisableActiveMigrationIsSet()
    {
        QuicTransportParameters parsedTransportParameters =
            QuicS18P2DisableActiveMigrationTestSupport.ParsePeerTransportParameters(
                QuicS18P2DisableActiveMigrationTestSupport.CreateDisableActiveMigrationPeerTransportParameters());

        using QuicConnectionRuntime runtime =
            QuicS18P2DisableActiveMigrationTestSupport.CreateRuntimeWithCommittedPeerTransportParameters(
                parsedTransportParameters);
        Assert.True(runtime.TransportFlags.HasFlag(QuicConnectionTransportState.DisableActiveMigration));

        QuicConnectionPathIdentity migrationPath =
            QuicS18P2DisableActiveMigrationTestSupport.CreateNewLocalAddressPath();
        byte[] datagram = QuicS18P2DisableActiveMigrationTestSupport.CreateDatagram();

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                migrationPath,
                datagram),
            nowTicks: 20).StateChanged);

        QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            migrationPath,
            observedAtTicks: 30);

        Assert.True(validationResult.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(QuicS18P2DisableActiveMigrationTestSupport.OriginalPath, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.CandidatePaths.TryGetValue(migrationPath, out QuicConnectionCandidatePathRecord candidatePath));
        Assert.True(candidatePath.Validation.IsValidated);
        Assert.False(candidatePath.Validation.IsAbandoned);
        Assert.DoesNotContain(validationResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promoteActivePathEffect
            && promoteActivePathEffect.PathIdentity == migrationPath);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0017")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ValidatedPeerRebindingCandidatePromotesWhenDisableActiveMigrationIsSet()
    {
        QuicTransportParameters parsedTransportParameters =
            QuicS18P2DisableActiveMigrationTestSupport.ParsePeerTransportParameters(
                QuicS18P2DisableActiveMigrationTestSupport.CreateDisableActiveMigrationPeerTransportParameters());

        using QuicConnectionRuntime runtime =
            QuicS18P2DisableActiveMigrationTestSupport.CreateRuntimeWithCommittedPeerTransportParameters(
                parsedTransportParameters);
        Assert.True(runtime.TransportFlags.HasFlag(QuicConnectionTransportState.DisableActiveMigration));

        QuicConnectionPathIdentity rebindingPath =
            QuicS18P2DisableActiveMigrationTestSupport.CreatePeerRebindingPath();
        byte[] datagram = QuicS18P2DisableActiveMigrationTestSupport.CreateDatagram();

        Assert.Equal(QuicS18P2DisableActiveMigrationTestSupport.OriginalPath.LocalAddress, rebindingPath.LocalAddress);
        Assert.Equal(QuicS18P2DisableActiveMigrationTestSupport.OriginalPath.LocalPort, rebindingPath.LocalPort);
        Assert.NotEqual(QuicS18P2DisableActiveMigrationTestSupport.OriginalPath.RemoteAddress, rebindingPath.RemoteAddress);

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                rebindingPath,
                datagram),
            nowTicks: 20).StateChanged);

        QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            rebindingPath,
            observedAtTicks: 30);

        Assert.True(validationResult.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(rebindingPath, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.ActivePath!.Value.IsValidated);
        Assert.False(runtime.CandidatePaths.ContainsKey(rebindingPath));
        Assert.Contains(validationResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promoteActivePathEffect
            && promoteActivePathEffect.PathIdentity == rebindingPath);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0017")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void PreferredAddressCandidateDoesNotPromoteBeforeValidationCompletesWhenDisableActiveMigrationIsSet()
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

        QuicConnectionTransitionResult receiveResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                preferredPath,
                datagram),
            nowTicks: 20);

        Assert.True(receiveResult.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(QuicS18P2DisableActiveMigrationTestSupport.OriginalPath, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.CandidatePaths.TryGetValue(preferredPath, out QuicConnectionCandidatePathRecord candidatePath));
        Assert.False(candidatePath.Validation.IsValidated);
        Assert.DoesNotContain(receiveResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promoteActivePathEffect
            && promoteActivePathEffect.PathIdentity == preferredPath);
    }
}
