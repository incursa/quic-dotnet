// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S9-2-P5-S1-R01")]
public sealed class RFC9000_S9_2_P5_S1_R01
{
    [Fact]
    [Requirement("RFC9000-S13-4-P2-S1-R01")]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2-0004")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void MigratingToANewLocalAddressReenablesEcnValidationOnTheNewPath()
    {
        QuicConnectionPathIdentity activePath = new(
            RemoteAddress: "203.0.113.70",
            LocalAddress: "198.51.100.70",
            RemotePort: 443,
            LocalPort: 61294);
        QuicConnectionPathIdentity migratedPath = new(
            RemoteAddress: "203.0.113.70",
            LocalAddress: "198.51.100.71",
            RemotePort: 443,
            LocalPort: 61295);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithConfirmedHandshakeAndActivePath(activePath);

        QuicPathMigrationRecoveryTestSupport.DirtyRecoveryState(runtime);
        QuicPathMigrationRecoverySnapshot dirty = QuicPathMigrationRecoveryTestSupport.CaptureRecoveryState(runtime);

        Assert.False(dirty.EcnValidated);

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

        QuicPathMigrationRecoverySnapshot afterPromotion = QuicPathMigrationRecoveryTestSupport.CaptureRecoveryState(runtime);

        Assert.True(afterPromotion.EcnValidated);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(migratedPath, runtime.ActivePath!.Value.Identity);
        Assert.Contains(validationResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promote
            && promote.PathIdentity == migratedPath
            && !promote.RestoreSavedState);
    }

    [Fact]
    [Requirement("RFC9000-S13-4-P2-S1-R01")]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2-0004")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void MigratingToANewLocalAddressResetsPriorEcnValidationCountsBeforeRevalidatingTheNewPath()
    {
        QuicConnectionPathIdentity activePath = new(
            RemoteAddress: "203.0.113.71",
            LocalAddress: "198.51.100.72",
            RemotePort: 443,
            LocalPort: 61296);
        QuicConnectionPathIdentity migratedPath = new(
            RemoteAddress: "203.0.113.71",
            LocalAddress: "198.51.100.73",
            RemotePort: 443,
            LocalPort: 61297);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithConfirmedHandshakeAndActivePath(activePath);

        QuicEcnValidationState oldPathEcnState = runtime.SendRuntime.EcnValidationState;
        oldPathEcnState.RecordPacketSent(QuicPacketNumberSpace.ApplicationData, QuicEcnMarking.Ect0);

        Assert.True(oldPathEcnState.TryValidateAcknowledgedEcnCounts(
            QuicPacketNumberSpace.ApplicationData,
            new QuicEcnCounts(1, 0, 0),
            newlyAcknowledgedEct0Packets: 1,
            newlyAcknowledgedEct1Packets: 0,
            largestAcknowledgedPacketNumberIncreased: true,
            out bool validationFailed));
        Assert.False(validationFailed);

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

        QuicEcnValidationState newPathEcnState = runtime.SendRuntime.EcnValidationState;
        newPathEcnState.RecordPacketSent(QuicPacketNumberSpace.ApplicationData, QuicEcnMarking.Ect0);

        Assert.True(newPathEcnState.IsEcnEnabled);
        Assert.True(newPathEcnState.TryValidateAcknowledgedEcnCounts(
            QuicPacketNumberSpace.ApplicationData,
            new QuicEcnCounts(1, 0, 0),
            newlyAcknowledgedEct0Packets: 1,
            newlyAcknowledgedEct1Packets: 0,
            largestAcknowledgedPacketNumberIncreased: true,
            out validationFailed));
        Assert.False(validationFailed);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(migratedPath, runtime.ActivePath!.Value.Identity);
        Assert.Contains(validationResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promote
            && promote.PathIdentity == migratedPath
            && !promote.RestoreSavedState);
    }

    [Fact]
    [Requirement("RFC9000-S13-4-P2-S1-R01")]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2-0004")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void MigratingToANewLocalAddressFuzz_RevalidatesEcnForEachNewPath()
    {
        foreach ((QuicConnectionPathIdentity ActivePath, QuicConnectionPathIdentity MigratedPath) testCase in new[]
        {
            (
                new QuicConnectionPathIdentity("203.0.113.80", "198.51.100.80", RemotePort: 443, LocalPort: 62000),
                new QuicConnectionPathIdentity("203.0.113.80", "198.51.100.81", RemotePort: 443, LocalPort: 62001)),
            (
                new QuicConnectionPathIdentity("203.0.113.81", "198.51.100.82", RemotePort: 4443, LocalPort: 62002),
                new QuicConnectionPathIdentity("203.0.113.81", "198.51.100.83", RemotePort: 4443, LocalPort: 62003)),
        })
        {
            QuicConnectionRuntime runtime =
                QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithConfirmedHandshakeAndActivePath(testCase.ActivePath);
            QuicPathMigrationRecoveryTestSupport.DirtyRecoveryState(runtime);
            Assert.False(QuicPathMigrationRecoveryTestSupport.CaptureRecoveryState(runtime).EcnValidated);

            Assert.True(runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: 20,
                    testCase.MigratedPath,
                    new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
                nowTicks: 20).StateChanged);

            QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
                runtime,
                testCase.MigratedPath,
                observedAtTicks: 30);
            QuicPathMigrationRecoverySnapshot afterValidation =
                QuicPathMigrationRecoveryTestSupport.CaptureRecoveryState(runtime);

            Assert.True(afterValidation.EcnValidated);
            Assert.True(runtime.SendRuntime.EcnValidationState.IsEcnEnabled);
            Assert.Equal(testCase.MigratedPath, runtime.ActivePath!.Value.Identity);
            Assert.Contains(validationResult.Effects, effect =>
                effect is QuicConnectionPromoteActivePathEffect promote
                && promote.PathIdentity == testCase.MigratedPath
                && !promote.RestoreSavedState);
        }
    }
}
