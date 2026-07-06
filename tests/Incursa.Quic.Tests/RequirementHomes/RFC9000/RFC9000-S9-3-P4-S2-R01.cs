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

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RecentlySeenPeerAddressesCanBypassAnotherValidationChallenge()
    {
        for (int iteration = 0; iteration < 4; iteration++)
        {
            QuicConnectionPathIdentity activePath = new(
                $"203.0.113.{120 + iteration}",
                $"198.51.100.{120 + iteration}",
                RemotePort: 443,
                LocalPort: 61300 + iteration);
            QuicConnectionPathIdentity firstValidatedPath = activePath with
            {
                RemoteAddress = $"203.0.113.{130 + iteration}",
                RemotePort = 7443 + iteration,
            };
            QuicConnectionPathIdentity secondValidatedPath = activePath with
            {
                RemoteAddress = $"203.0.113.{140 + iteration}",
                RemotePort = 8443 + iteration,
            };
            QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(activePath);
            byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

            Assert.True(runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: 20 + iteration,
                    firstValidatedPath,
                    datagram),
                nowTicks: 20 + iteration).StateChanged);

            Assert.True(QuicPathMigrationRecoveryTestSupport.ValidatePath(
                runtime,
                firstValidatedPath,
                observedAtTicks: 30 + iteration).StateChanged);

            Assert.True(runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: 40 + iteration,
                    secondValidatedPath,
                    datagram),
                nowTicks: 40 + iteration).StateChanged);

            Assert.True(QuicPathMigrationRecoveryTestSupport.ValidatePath(
                runtime,
                secondValidatedPath,
                observedAtTicks: 50 + iteration).StateChanged);
            Assert.True(runtime.RecentlyValidatedPaths.ContainsKey(firstValidatedPath));
            Assert.True(runtime.ActivePath.HasValue);
            Assert.Equal(secondValidatedPath, runtime.ActivePath!.Value.Identity);

            QuicConnectionTransitionResult reuseResult = runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: 60 + iteration,
                    firstValidatedPath,
                    datagram),
                nowTicks: 60 + iteration);

            Assert.True(reuseResult.StateChanged);
            Assert.True(runtime.ActivePath.HasValue);
            Assert.Equal(firstValidatedPath, runtime.ActivePath!.Value.Identity);
            Assert.False(runtime.CandidatePaths.ContainsKey(firstValidatedPath));
            Assert.Contains(reuseResult.Effects, effect =>
                effect is QuicConnectionPromoteActivePathEffect promote
                && promote.PathIdentity == firstValidatedPath);
            Assert.DoesNotContain(reuseResult.Effects, effect => effect is QuicConnectionSendDatagramEffect);
        }
    }
}
