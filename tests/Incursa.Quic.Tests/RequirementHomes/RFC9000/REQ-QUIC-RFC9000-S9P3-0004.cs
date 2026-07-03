// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S9-3-P4-S2-R01")]
public sealed class REQ_QUIC_RFC9000_S9P3_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RecentlyValidatedPeerAddressCanBypassAnotherValidationChallengeAndPromote()
    {
        QuicConnectionPathIdentity activePath = new("203.0.113.104", RemotePort: 443);
        QuicConnectionPathIdentity firstValidatedPath = new("203.0.113.105", RemotePort: 443);
        QuicConnectionPathIdentity secondValidatedPath = new("203.0.113.106", RemotePort: 443);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(activePath);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                firstValidatedPath,
                datagram),
            nowTicks: 20).StateChanged);

        QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            firstValidatedPath,
            observedAtTicks: 30);

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 40,
                secondValidatedPath,
                datagram),
            nowTicks: 40).StateChanged);

        QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            secondValidatedPath,
            observedAtTicks: 50);

        Assert.True(runtime.Transition(
            new QuicConnectionTransportParametersCommittedEvent(
                ObservedAtTicks: 60,
                TransportFlags: QuicConnectionTransportState.DisableActiveMigration),
            nowTicks: 60).StateChanged);

        QuicConnectionTransitionResult reuseResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 70,
                firstValidatedPath,
                datagram),
            nowTicks: 70);

        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(firstValidatedPath, runtime.ActivePath!.Value.Identity);
        Assert.False(runtime.CandidatePaths.ContainsKey(firstValidatedPath));
        Assert.Contains(reuseResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promote
            && promote.PathIdentity == firstValidatedPath);
        Assert.DoesNotContain(reuseResult.Effects, effect => effect is QuicConnectionSendDatagramEffect);
    }
}
