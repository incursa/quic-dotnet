// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_MigrationOutcome_DeferredFuzzClosure
{
    private static readonly byte[] InitialSourceConnectionId = [0x10, 0x11, 0x12, 0x13];
    private static readonly byte[] PreferredConnectionId = [0x20, 0x21, 0x22, 0x23];
    private static readonly byte[] PreferredStatelessResetToken =
    [
        0x30, 0x31, 0x32, 0x33,
        0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3A, 0x3B,
        0x3C, 0x3D, 0x3E, 0x3F,
    ];

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0278")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void PreferredAddressMigrationFuzz_IgnoresDisableActiveMigrationAfterPreferredAddressValidation()
    {
        for (int iteration = 0; iteration < 8; iteration++)
        {
            QuicConnectionPathIdentity originalPath = new($"203.0.113.{20 + iteration}", RemotePort: 443);
            QuicPreferredAddress preferredAddress = CreatePreferredAddress(iteration);
            QuicConnectionPathIdentity preferredPath = new(
                new IPAddress(preferredAddress.IPv4Address).ToString(),
                RemotePort: preferredAddress.IPv4Port);
            QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(originalPath);
            QuicPathMigrationRecoveryTestSupport.CommitPeerTransportParameters(
                runtime,
                new QuicTransportParameters
                {
                    InitialSourceConnectionId = InitialSourceConnectionId,
                    DisableActiveMigration = true,
                    PreferredAddress = preferredAddress,
                });

            Assert.True(runtime.TlsState.PeerTransportParameters!.DisableActiveMigration);

            QuicConnectionTransitionResult receiveResult = runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: 20 + iteration,
                    preferredPath,
                    new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
                nowTicks: 20 + iteration);

            Assert.True(receiveResult.StateChanged);
            Assert.Equal(originalPath, runtime.ActivePath!.Value.Identity);
            Assert.True(runtime.CandidatePaths.TryGetValue(preferredPath, out QuicConnectionCandidatePathRecord candidatePath));
            Assert.False(candidatePath.Validation.IsValidated);

            QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
                runtime,
                preferredPath,
                observedAtTicks: 40 + iteration);

            Assert.True(validationResult.StateChanged);
            Assert.Equal(preferredPath, runtime.ActivePath!.Value.Identity);
            Assert.True(runtime.ActivePath!.Value.IsValidated);
            Assert.Equal(preferredPath.RemoteAddress, runtime.LastValidatedRemoteAddress);
            Assert.DoesNotContain(preferredPath, runtime.CandidatePaths.Keys);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0460")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void HandshakeConfirmationFuzz_DoesNotMigrateBeforeHandshakeConfirmation()
    {
        for (int iteration = 0; iteration < 8; iteration++)
        {
            QuicConnectionPathIdentity activePath = new(
                RemoteAddress: $"203.0.113.{40 + iteration}",
                LocalAddress: $"198.51.100.{40 + iteration}",
                RemotePort: 443,
                LocalPort: (ushort)(61000 + iteration));
            QuicConnectionPathIdentity migratedPath = activePath with
            {
                LocalPort = activePath.LocalPort + 100,
            };
            QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePathBeforeHandshakeConfirmation(activePath);

            Assert.False(runtime.HandshakeConfirmed);

            QuicConnectionTransitionResult receiveResult = runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: 20 + iteration,
                    migratedPath,
                    new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
                nowTicks: 20 + iteration);

            Assert.True(receiveResult.StateChanged);
            Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);
            Assert.True(runtime.CandidatePaths.TryGetValue(migratedPath, out QuicConnectionCandidatePathRecord candidatePath));
            Assert.False(candidatePath.Validation.IsValidated);

            QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
                runtime,
                migratedPath,
                observedAtTicks: 40 + iteration);

            Assert.True(validationResult.StateChanged);
            Assert.False(runtime.HandshakeConfirmed);
            Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);
            Assert.True(runtime.CandidatePaths.TryGetValue(migratedPath, out candidatePath));
            Assert.True(candidatePath.Validation.IsValidated);
            Assert.DoesNotContain(validationResult.Effects, effect =>
                effect is QuicConnectionPromoteActivePathEffect promote
                && promote.PathIdentity == migratedPath);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0488")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void AddressValidationTokenFuzz_ServerEmitsTokenOnlyForNewlyValidatedClientAddresses()
    {
        for (int iteration = 0; iteration < 8; iteration++)
        {
            QuicConnectionRuntime runtime = QuicS9P3TokenEmissionTestSupport.CreateServerRuntimeReadyForTokenEmission();
            QuicConnectionPathIdentity validatedPath = new($"203.0.113.{70 + iteration}", RemotePort: 443);

            Assert.True(runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: 20 + iteration,
                    validatedPath,
                    new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
                nowTicks: 20 + iteration).StateChanged);

            QuicConnectionTransitionResult firstValidationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
                runtime,
                validatedPath,
                observedAtTicks: 40 + iteration);
            QuicConnectionTransitionResult repeatValidationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
                runtime,
                validatedPath,
                observedAtTicks: 60 + iteration);

            Assert.Equal(validatedPath, runtime.ActivePath!.Value.Identity);
            Assert.Equal(validatedPath.RemoteAddress, runtime.LastValidatedRemoteAddress);
            Assert.Contains(firstValidationResult.Effects, effect =>
                effect is QuicConnectionSendDatagramEffect send
                && send.PathIdentity == validatedPath);
            Assert.DoesNotContain(repeatValidationResult.Effects, effect => effect is QuicConnectionSendDatagramEffect);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0495")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ValidationFailureFuzz_DiscardsConnectionStateWhenNoPeerAddressWasValidated()
    {
        for (int iteration = 0; iteration < 8; iteration++)
        {
            QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(
                new QuicConnectionPathIdentity($"203.0.113.{90 + iteration}", RemotePort: 443));
            QuicConnectionPathIdentity failedPath = new($"203.0.113.{100 + iteration}", RemotePort: 443);

            Assert.False(runtime.HasValidatedPath);
            Assert.Null(runtime.LastValidatedRemoteAddress);

            QuicConnectionTransitionResult failureResult = runtime.Transition(
                new QuicConnectionPathValidationFailedEvent(
                    ObservedAtTicks: 20 + iteration,
                    failedPath,
                    IsAbandoned: true),
                nowTicks: 20 + iteration);

            Assert.True(failureResult.StateChanged);
            Assert.Equal(QuicConnectionPhase.Discarded, runtime.Phase);
            Assert.Equal(QuicConnectionSendingMode.None, runtime.SendingMode);
            Assert.False(runtime.CanSendOrdinaryPackets);
            Assert.Contains(failureResult.Effects, effect => effect is QuicConnectionDiscardConnectionStateEffect);
            Assert.DoesNotContain(failureResult.Effects, effect => effect is QuicConnectionPromoteActivePathEffect);
        }
    }

    private static QuicPreferredAddress CreatePreferredAddress(int iteration)
    {
        byte lowByte = (byte)(120 + iteration);
        return new QuicPreferredAddress
        {
            IPv4Address = [198, 51, 100, lowByte],
            IPv4Port = (ushort)(9400 + iteration),
            IPv6Address =
            [
                0x20, 0x01, 0x0D, 0xB8,
                0x00, 0x01, 0x00, 0x02,
                0x00, 0x03, 0x00, 0x04,
                0x00, 0x05, 0x00, lowByte,
            ],
            IPv6Port = (ushort)(9500 + iteration),
            ConnectionId = PreferredConnectionId,
            StatelessResetToken = PreferredStatelessResetToken,
        };
    }
}
