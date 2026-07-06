// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_MigrationState_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0412")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ChangedAddressAntiAmplificationFuzz_EnforcesThreeTimesAttributedPayloadBudget()
    {
        for (int iteration = 0; iteration < 16; iteration++)
        {
            int receivedBytes = 1 + (iteration * 257);
            int allowedSendBytes = receivedBytes * 3;
            QuicAntiAmplificationBudget budget = new();

            Assert.True(budget.TryRegisterReceivedDatagramPayloadBytes(receivedBytes, uniquelyAttributedToSingleConnection: true));
            Assert.Equal((ulong)receivedBytes, budget.ReceivedPayloadBytes);
            Assert.Equal((ulong)allowedSendBytes, budget.RemainingSendBudget);
            Assert.True(budget.CanSend(allowedSendBytes));
            Assert.False(budget.CanSend(allowedSendBytes + 1));

            int firstSend = allowedSendBytes / 2;
            Assert.True(budget.TryConsumeSendBudget(firstSend));
            Assert.True(budget.TryConsumeSendBudget(allowedSendBytes - firstSend));
            Assert.Equal(0UL, budget.RemainingSendBudget);
            Assert.False(budget.TryConsumeSendBudget(1));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0518")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ZeroLengthConnectionIdMigrationFuzz_PromotesOnlyWhenPeerUsesNonZeroLengthConnectionId()
    {
        for (int iteration = 0; iteration < 8; iteration++)
        {
            QuicConnectionPathIdentity activePath = new(
                RemoteAddress: $"203.0.113.{120 + iteration}",
                LocalAddress: $"198.51.100.{120 + iteration}",
                RemotePort: 443,
                LocalPort: (ushort)(61000 + iteration));

            AssertMigrationPromotionForPeerInitialSourceConnectionId(
                activePath,
                migratedPath: activePath with
                {
                    RemoteAddress = $"203.0.113.{140 + iteration}",
                },
                initialSourceConnectionId: [(byte)(0x70 + iteration)],
                expectedPromoted: true,
                observedAtTicks: 20 + iteration);

            AssertMigrationPromotionForPeerInitialSourceConnectionId(
                activePath,
                migratedPath: activePath with
                {
                    RemoteAddress = $"203.0.113.{160 + iteration}",
                    LocalAddress = $"198.51.100.{160 + iteration}",
                },
                initialSourceConnectionId: [],
                expectedPromoted: false,
                observedAtTicks: 40 + iteration);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0519")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void RepeatedValidatedMigrationFuzz_ResetsPathRecoveryForEachAddressChange()
    {
        for (int iteration = 0; iteration < 8; iteration++)
        {
            QuicConnectionPathIdentity activePath = new($"203.0.113.{180 + iteration}", RemotePort: 443);
            QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(activePath);
            QuicPathMigrationRecoverySnapshot baseline = QuicPathMigrationRecoveryTestSupport.CaptureRecoveryState(runtime);

            for (int migrationOrdinal = 0; migrationOrdinal < 3; migrationOrdinal++)
            {
                QuicConnectionPathIdentity migratedPath = new(
                    $"203.0.113.{200 + iteration + (migrationOrdinal * 16)}",
                    RemotePort: (ushort)(443 + migrationOrdinal));

                QuicPathMigrationRecoveryTestSupport.DirtyRecoveryState(runtime);
                Assert.NotEqual(baseline, QuicPathMigrationRecoveryTestSupport.CaptureRecoveryState(runtime));

                Assert.True(runtime.Transition(
                    new QuicConnectionPacketReceivedEvent(
                        ObservedAtTicks: 20 + iteration + migrationOrdinal,
                        migratedPath,
                        new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
                    nowTicks: 20 + iteration + migrationOrdinal).StateChanged);

                Assert.True(QuicPathMigrationRecoveryTestSupport.ValidatePath(
                    runtime,
                    migratedPath,
                    observedAtTicks: 40 + iteration + migrationOrdinal).StateChanged);

                Assert.Equal(baseline, QuicPathMigrationRecoveryTestSupport.CaptureRecoveryState(runtime));
                Assert.Equal(migratedPath, runtime.ActivePath!.Value.Identity);
                Assert.Equal(migratedPath.RemoteAddress, runtime.LastValidatedRemoteAddress);
            }
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S9P2-0003")]
    [Requirement("REQ-QUIC-RFC9000-S9P2-0004")]
    [Requirement("REQ-QUIC-RFC9000-S9P4-0003")]
    [Requirement("REQ-QUIC-RFC9000-S9P4-0005")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void AddressChangeVsPortOnlyMigrationFuzz_ResetsOrRetainsRecoveryStateByPathIdentity()
    {
        for (int iteration = 0; iteration < 8; iteration++)
        {
            QuicConnectionPathIdentity activePath = new(
                RemoteAddress: $"203.0.113.{30 + iteration}",
                LocalAddress: $"198.51.100.{30 + iteration}",
                RemotePort: 443,
                LocalPort: (ushort)(61000 + iteration));

            AssertAddressChangeResetsRecoveryState(
                activePath,
                activePath with
                {
                    LocalAddress = $"198.51.100.{60 + iteration}",
                    LocalPort = (ushort)(62000 + iteration),
                },
                observedAtTicks: 20 + iteration);

            AssertPortOnlyPromotionRetainsRecoveryState(
                activePath,
                activePath with
                {
                    RemotePort = (ushort)(8443 + iteration),
                },
                observedAtTicks: 40 + iteration);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0520")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ProvidedConnectionIdRoutingFuzz_RoutesOnlyRegisteredConnectionIdsAfterMigration()
    {
        for (int iteration = 0; iteration < 8; iteration++)
        {
            using QuicConnectionRuntimeEndpoint endpoint = new(4);
            using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
            QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
            QuicConnectionPathIdentity activePath = new(
                $"203.0.113.{40 + iteration}",
                $"198.51.100.{40 + iteration}",
                443,
                61234);
            QuicConnectionPathIdentity migratedPath = activePath with
            {
                RemoteAddress = $"203.0.113.{60 + iteration}",
                LocalAddress = $"198.51.100.{60 + iteration}",
                LocalPort = 61334,
            };
            byte[] registeredConnectionId = [(byte)(0x80 + iteration), (byte)(0x90 + iteration)];
            byte[] unregisteredConnectionId = [(byte)(0xA0 + iteration), (byte)(0xB0 + iteration)];

            Assert.True(endpoint.TryRegisterConnection(handle, runtime));
            Assert.True(endpoint.TryUpdateEndpointBinding(handle, activePath));
            Assert.True(endpoint.TryRegisterConnectionId(handle, registeredConnectionId));
            Assert.True(endpoint.TryUpdateEndpointBinding(handle, migratedPath));

            QuicConnectionIngressResult routedResult = endpoint.ReceiveDatagram(
                QuicHeaderTestData.BuildShortHeader(0x00, [.. registeredConnectionId, 0x01]),
                migratedPath);
            QuicConnectionIngressResult unroutableResult = endpoint.ReceiveDatagram(
                QuicHeaderTestData.BuildShortHeader(0x00, [.. unregisteredConnectionId, 0x01]),
                migratedPath);

            Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, routedResult.Disposition);
            Assert.Equal(handle, routedResult.Handle);
            Assert.Equal(QuicConnectionIngressDisposition.Unroutable, unroutableResult.Disposition);
            Assert.Equal(QuicConnectionEndpointHandlingKind.None, unroutableResult.HandlingKind);
            Assert.Null(unroutableResult.Handle);
        }
    }

    private static void AssertAddressChangeResetsRecoveryState(
        QuicConnectionPathIdentity activePath,
        QuicConnectionPathIdentity migratedPath,
        long observedAtTicks)
    {
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithConfirmedHandshakeAndActivePath(activePath);
        QuicPathMigrationRecoverySnapshot baseline = QuicPathMigrationRecoveryTestSupport.CaptureRecoveryState(runtime);

        QuicPathMigrationRecoveryTestSupport.DirtyRecoveryState(runtime);
        Assert.NotEqual(baseline, QuicPathMigrationRecoveryTestSupport.CaptureRecoveryState(runtime));

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: observedAtTicks,
                migratedPath,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: observedAtTicks).StateChanged);

        QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            migratedPath,
            observedAtTicks: observedAtTicks + 10);

        Assert.Equal(baseline, QuicPathMigrationRecoveryTestSupport.CaptureRecoveryState(runtime));
        Assert.Equal(migratedPath, runtime.ActivePath!.Value.Identity);
        Assert.Contains(validationResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promote
            && promote.PathIdentity == migratedPath
            && !promote.RestoreSavedState);
    }

    private static void AssertPortOnlyPromotionRetainsRecoveryState(
        QuicConnectionPathIdentity activePath,
        QuicConnectionPathIdentity portOnlyPath,
        long observedAtTicks)
    {
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithConfirmedHandshakeAndActivePath(activePath);

        QuicPathMigrationRecoveryTestSupport.DirtyRecoveryState(runtime);

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: observedAtTicks,
                portOnlyPath,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: observedAtTicks).StateChanged);
        QuicPathMigrationRecoverySnapshot afterValidationProbe =
            QuicPathMigrationRecoveryTestSupport.CaptureRecoveryState(runtime);

        QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            portOnlyPath,
            observedAtTicks: observedAtTicks + 10);

        Assert.Equal(afterValidationProbe, QuicPathMigrationRecoveryTestSupport.CaptureRecoveryState(runtime));
        Assert.Equal(portOnlyPath, runtime.ActivePath!.Value.Identity);
        Assert.Contains(validationResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promote
            && promote.PathIdentity == portOnlyPath
            && promote.RestoreSavedState);
    }

    private static void AssertMigrationPromotionForPeerInitialSourceConnectionId(
        QuicConnectionPathIdentity activePath,
        QuicConnectionPathIdentity migratedPath,
        byte[] initialSourceConnectionId,
        bool expectedPromoted,
        long observedAtTicks)
    {
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(activePath);
        QuicPathMigrationRecoveryTestSupport.CommitPeerTransportParameters(
            runtime,
            new QuicTransportParameters
            {
                InitialSourceConnectionId = initialSourceConnectionId,
            });

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: observedAtTicks,
                migratedPath,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: observedAtTicks).StateChanged);

        QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            migratedPath,
            observedAtTicks: observedAtTicks + 10);

        Assert.True(validationResult.StateChanged);
        if (expectedPromoted)
        {
            Assert.Equal(migratedPath, runtime.ActivePath!.Value.Identity);
            Assert.Equal(migratedPath.RemoteAddress, runtime.LastValidatedRemoteAddress);
            Assert.Contains(validationResult.Effects, effect =>
                effect is QuicConnectionPromoteActivePathEffect promote
                && promote.PathIdentity == migratedPath
                && !promote.RestoreSavedState);
        }
        else
        {
            Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);
            Assert.True(runtime.CandidatePaths.TryGetValue(migratedPath, out QuicConnectionCandidatePathRecord candidatePath));
            Assert.True(candidatePath.Validation.IsValidated);
            Assert.DoesNotContain(validationResult.Effects, effect =>
                effect is QuicConnectionPromoteActivePathEffect promote
                && promote.PathIdentity == migratedPath);
        }
    }
}
