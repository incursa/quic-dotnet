// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S9P5_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S9P5-0004")]
    [Requirement("REQ-QUIC-RFC9000-S9P5-0009")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public async Task Fuzz_PeerSourceAddressRebindingCanContinueWithCurrentConnectionIdAndLocalAddress()
    {
        foreach ((byte seed, int connectionIdLength, ushort remotePort) in new[]
        {
            ((byte)0x20, 1, (ushort)443),
            ((byte)0x30, 4, (ushort)8443),
            ((byte)0x40, QuicConnectionIdKey.MaximumLength, ushort.MaxValue),
        })
        {
            using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
            QuicConnectionPathIdentity originalPath = runtime.ActivePath!.Value.Identity;
            QuicConnectionPathIdentity reboundPath = new(
                $"203.0.113.{seed}",
                originalPath.LocalAddress,
                remotePort,
                originalPath.LocalPort);
            byte[] currentConnectionId = CreateConnectionId(seed, connectionIdLength);

            await REQ_QUIC_RFC9000_0244.BindPeerConnectionIdToCurrentPath(runtime, currentConnectionId);
            QuicConnectionTransitionResult validationResult = REQ_QUIC_RFC9000_0244.ValidateMigratedPath(runtime, reboundPath);

            Assert.True(validationResult.StateChanged);
            Assert.Equal(reboundPath, runtime.ActivePath!.Value.Identity);
            Assert.Equal(originalPath.LocalAddress, runtime.ActivePath.Value.Identity.LocalAddress);
            Assert.Equal(originalPath.LocalPort, runtime.ActivePath.Value.Identity.LocalPort);
            Assert.Equal(currentConnectionId, runtime.CurrentPeerDestinationConnectionId.ToArray());
            Assert.Contains(validationResult.Effects, effect =>
                effect is QuicConnectionPromoteActivePathEffect promote
                && promote.PathIdentity == reboundPath
                && !promote.RestoreSavedState);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S9P5-0005")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ZeroLengthPeerConnectionIdBlocksEndpointInitiatedAddressMigrationButAllowsPeerRebinding()
    {
        foreach ((byte seed, bool sameLocalAddress) in new[]
        {
            ((byte)0x50, false),
            ((byte)0x60, true),
        })
        {
            QuicConnectionPathIdentity activePath = new(
                $"203.0.113.{seed}",
                $"198.51.100.{seed}",
                RemotePort: 443,
                LocalPort: 61234);
            QuicConnectionPathIdentity migratedPath = new(
                $"203.0.113.{seed + 1}",
                sameLocalAddress ? activePath.LocalAddress : $"198.51.100.{seed + 1}",
                RemotePort: 8443,
                LocalPort: activePath.LocalPort);
            using QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithConfirmedHandshakeAndActivePath(
                activePath,
                new QuicTransportParameters
                {
                    InitialSourceConnectionId = [],
                });

            ReceivePacketOnPath(runtime, migratedPath, observedAtTicks: 20);
            QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
                runtime,
                migratedPath,
                observedAtTicks: 30);

            Assert.True(validationResult.StateChanged);
            Assert.True(runtime.ActivePath.HasValue);
            if (sameLocalAddress)
            {
                Assert.Equal(migratedPath, runtime.ActivePath.Value.Identity);
                Assert.Equal(0, runtime.CurrentPeerDestinationConnectionId.Length);
                Assert.Contains(validationResult.Effects, effect =>
                    effect is QuicConnectionPromoteActivePathEffect promote
                    && promote.PathIdentity == migratedPath);
            }
            else
            {
                Assert.Equal(activePath, runtime.ActivePath.Value.Identity);
                Assert.True(runtime.CandidatePaths.TryGetValue(migratedPath, out QuicConnectionCandidatePathRecord candidatePath));
                Assert.True(candidatePath.Validation.IsValidated);
                Assert.DoesNotContain(validationResult.Effects, effect =>
                    effect is QuicConnectionPromoteActivePathEffect promote
                    && promote.PathIdentity == migratedPath);
            }
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S9P5-0006")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AddressChangesResetDirtyRecoveryStateAcrossRepresentativePaths()
    {
        foreach ((byte seed, ushort localPort) in new[]
        {
            ((byte)0x70, (ushort)61234),
            ((byte)0x80, (ushort)65535),
        })
        {
            QuicConnectionPathIdentity activePath = new(
                $"203.0.113.{seed}",
                $"198.51.100.{seed}",
                RemotePort: 443,
                LocalPort: localPort);
            QuicConnectionPathIdentity migratedPath = new(
                $"203.0.113.{seed + 1}",
                $"198.51.100.{seed + 1}",
                RemotePort: 443,
                LocalPort: localPort);
            using QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(activePath);
            QuicPathMigrationRecoverySnapshot baseline = QuicPathMigrationRecoveryTestSupport.CaptureRecoveryState(runtime);

            QuicPathMigrationRecoveryTestSupport.DirtyRecoveryState(runtime);
            Assert.NotEqual(baseline, QuicPathMigrationRecoveryTestSupport.CaptureRecoveryState(runtime));
            ReceivePacketOnPath(runtime, migratedPath, observedAtTicks: 20);
            QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
                runtime,
                migratedPath,
                observedAtTicks: 30);

            Assert.True(validationResult.StateChanged);
            Assert.Equal(baseline, QuicPathMigrationRecoveryTestSupport.CaptureRecoveryState(runtime));
            Assert.Equal(migratedPath, runtime.ActivePath!.Value.Identity);
            Assert.Equal(migratedPath.RemoteAddress, runtime.LastValidatedRemoteAddress);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S9P5-0007")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PreIssuedConnectionIdsRouteMigratedPacketsAndUnissuedConnectionIdsDoNot()
    {
        foreach ((byte seed, int connectionIdLength) in new[]
        {
            ((byte)0x90, 1),
            ((byte)0xA0, 8),
            ((byte)0xB0, QuicConnectionIdKey.MaximumLength),
        })
        {
            using QuicConnectionRuntimeEndpoint endpoint = new(2);
            using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
            QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
            QuicConnectionPathIdentity activePath = new($"203.0.113.{seed}", $"198.51.100.{seed}", 443, 61234);
            QuicConnectionPathIdentity migratedPath = new($"203.0.113.{seed + 1}", $"198.51.100.{seed + 1}", 443, 61235);
            byte[] issuedConnectionId = CreateConnectionId(seed, connectionIdLength);
            byte[] unissuedConnectionId = CreateConnectionId((byte)(seed + 0x10), connectionIdLength);

            Assert.True(endpoint.TryRegisterConnection(handle, runtime));
            Assert.True(endpoint.TryUpdateEndpointBinding(handle, activePath));
            Assert.True(endpoint.TryRegisterConnectionId(handle, issuedConnectionId));
            Assert.True(endpoint.TryUpdateEndpointBinding(handle, migratedPath));

            QuicConnectionIngressResult issuedResult = endpoint.ReceiveDatagram(
                QuicHeaderTestData.BuildShortHeader(0x00, issuedConnectionId),
                migratedPath);
            QuicConnectionIngressResult unissuedResult = endpoint.ReceiveDatagram(
                QuicHeaderTestData.BuildShortHeader(0x00, unissuedConnectionId),
                migratedPath);

            Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, issuedResult.Disposition);
            Assert.Equal(handle, issuedResult.Handle);
            Assert.Equal(QuicConnectionIngressDisposition.Unroutable, unissuedResult.Disposition);
            Assert.Null(unissuedResult.Handle);
        }
    }

    private static void ReceivePacketOnPath(
        QuicConnectionRuntime runtime,
        QuicConnectionPathIdentity pathIdentity,
        long observedAtTicks)
    {
        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: observedAtTicks,
                pathIdentity,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: observedAtTicks).StateChanged);
    }

    private static byte[] CreateConnectionId(byte seed, int length)
    {
        byte[] connectionId = new byte[length];
        for (int index = 0; index < connectionId.Length; index++)
        {
            connectionId[index] = (byte)(seed + index);
        }

        return connectionId;
    }
}
