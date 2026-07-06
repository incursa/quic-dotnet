// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S9_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S9-0002")]
    [Requirement("REQ-QUIC-RFC9000-S9-0009")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void DisableActiveMigrationFuzz_DoesNotPromoteNonPreferredLocalAddressChanges()
    {
        QuicConnectionPathIdentity[] nonPreferredPaths =
        [
            new(
                QuicS18P2DisableActiveMigrationTestSupport.OriginalPath.RemoteAddress,
                "198.51.100.10",
                QuicS18P2DisableActiveMigrationTestSupport.OriginalPath.RemotePort,
                LocalPort: 61240),
            new(
                QuicS18P2DisableActiveMigrationTestSupport.OriginalPath.RemoteAddress,
                "198.51.100.11",
                QuicS18P2DisableActiveMigrationTestSupport.OriginalPath.RemotePort,
                LocalPort: 61241),
            new(
                QuicS18P2DisableActiveMigrationTestSupport.OriginalPath.RemoteAddress,
                "198.51.100.12",
                QuicS18P2DisableActiveMigrationTestSupport.OriginalPath.RemotePort,
                LocalPort: 61242),
        ];

        foreach (QuicConnectionPathIdentity nonPreferredPath in nonPreferredPaths)
        {
            QuicTransportParameters parsedTransportParameters =
                QuicS18P2DisableActiveMigrationTestSupport.ParsePeerTransportParameters(
                    QuicS18P2DisableActiveMigrationTestSupport.CreatePreferredAddressPeerTransportParameters());

            using QuicConnectionRuntime runtime =
                QuicS18P2DisableActiveMigrationTestSupport.CreateRuntimeWithCommittedPeerTransportParameters(
                    parsedTransportParameters);
            Assert.True(runtime.TransportFlags.HasFlag(QuicConnectionTransportState.DisableActiveMigration));

            Assert.True(runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: 20,
                    nonPreferredPath,
                    QuicS18P2DisableActiveMigrationTestSupport.CreateDatagram()),
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
            Assert.DoesNotContain(validationResult.Effects, effect =>
                effect is QuicConnectionPromoteActivePathEffect promote
                && promote.PathIdentity == nonPreferredPath);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S9-0008")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void PreHandshakeMigrationFuzz_DelaysPromotionUntilHandshakeConfirmation()
    {
        for (int iteration = 0; iteration < 8; iteration++)
        {
            QuicConnectionPathIdentity activePath = new(
                RemoteAddress: $"203.0.113.{40 + iteration}",
                LocalAddress: $"198.51.100.{40 + iteration}",
                RemotePort: 443,
                LocalPort: 61300 + iteration);
            QuicConnectionPathIdentity migratedPath = new(
                RemoteAddress: activePath.RemoteAddress,
                LocalAddress: $"198.51.100.{80 + iteration}",
                RemotePort: activePath.RemotePort,
                LocalPort: 61400 + iteration);
            QuicConnectionRuntime runtime =
                QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePathBeforeHandshakeConfirmation(activePath);

            Assert.False(runtime.HandshakeConfirmed);

            Assert.True(runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: 20,
                    migratedPath,
                    new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
                nowTicks: 20).StateChanged);

            QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
                runtime,
                migratedPath,
                observedAtTicks: 30);

            Assert.True(validationResult.StateChanged);
            Assert.False(runtime.HandshakeConfirmed);
            Assert.True(runtime.ActivePath.HasValue);
            Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);
            Assert.True(runtime.CandidatePaths.TryGetValue(migratedPath, out QuicConnectionCandidatePathRecord candidatePath));
            Assert.True(candidatePath.Validation.IsValidated);
            Assert.DoesNotContain(validationResult.Effects, effect =>
                effect is QuicConnectionPromoteActivePathEffect promote
                && promote.PathIdentity == migratedPath);
        }
    }
}
