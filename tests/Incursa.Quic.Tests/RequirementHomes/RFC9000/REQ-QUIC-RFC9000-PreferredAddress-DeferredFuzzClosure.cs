// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_PreferredAddress_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0525")]
    [Requirement("REQ-QUIC-RFC9000-0529")]
    [Requirement("REQ-QUIC-RFC9000-0542")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void PreferredAddressValidationFuzz_ChoosesAndValidatesPreferredAddressesBeforePromotion()
    {
        for (int iteration = 0; iteration < 6; iteration++)
        {
            QuicPreferredAddress preferredAddress = CreatePreferredAddress(iteration);
            QuicConnectionPathIdentity activePath = new($"203.0.113.{30 + iteration}", RemotePort: 443);
            QuicConnectionPathIdentity preferredPath = CreatePreferredPath(preferredAddress);
            using QuicConnectionRuntime runtime = QuicS9P6P1PreferredAddressTestSupport.CreateClientRuntime(
                activePath,
                preferredAddress);

            Assert.False(runtime.HandshakeConfirmed);
            Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);
            Assert.False(runtime.CandidatePaths.ContainsKey(preferredPath));

            QuicConnectionTransitionResult handshakeResult = QuicS9P6P1PreferredAddressTestSupport.ConfirmHandshake(
                runtime,
                observedAtTicks: 20 + iteration);

            Assert.True(handshakeResult.StateChanged);
            Assert.True(runtime.HandshakeConfirmed);
            Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);
            Assert.True(runtime.CandidatePaths.TryGetValue(preferredPath, out QuicConnectionCandidatePathRecord candidatePath));
            Assert.False(candidatePath.Validation.IsValidated);
            Assert.False(candidatePath.Validation.IsAbandoned);
            Assert.Equal(1UL, candidatePath.Validation.ChallengeSendCount);
            QuicS9P6P1PreferredAddressTestSupport.AssertPathChallengeSent(runtime, handshakeResult, preferredPath);

            QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
                runtime,
                preferredPath,
                observedAtTicks: 40 + iteration);

            Assert.True(validationResult.StateChanged);
            Assert.Equal(preferredPath, runtime.ActivePath!.Value.Identity);
            Assert.Equal(preferredPath.RemoteAddress, runtime.LastValidatedRemoteAddress);
            Assert.False(runtime.CandidatePaths.ContainsKey(preferredPath));
            Assert.True(runtime.RecentlyValidatedPaths.ContainsKey(preferredPath));
            Assert.Contains(validationResult.Effects, effect =>
                effect is QuicConnectionPromoteActivePathEffect promote
                && promote.PathIdentity == preferredPath
                && !promote.RestoreSavedState);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0531")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void PreferredAddressOriginalAddressFuzz_SendsNonProbingTrafficFromOriginalAddressUntilValidation()
    {
        for (int iteration = 0; iteration < 6; iteration++)
        {
            QuicPreferredAddress preferredAddress = CreatePreferredAddress(iteration);
            QuicTransportParameters transportParameters = CreatePeerTransportParameters(preferredAddress);
            QuicConnectionPathIdentity activePath = new($"203.0.113.{60 + iteration}", RemotePort: 443);
            QuicConnectionPathIdentity preferredPath = CreatePreferredPath(preferredAddress);
            using QuicConnectionRuntime runtime =
                QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithOneRttKeysAndCommittedPeerTransportParameters(
                    activePath,
                    transportParameters);

            QuicConnectionTransitionResult receiveResult = runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: 20 + iteration,
                    preferredPath,
                    new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
                nowTicks: 20 + iteration);

            Assert.True(receiveResult.StateChanged);
            Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);
            Assert.True(runtime.CandidatePaths.TryGetValue(preferredPath, out QuicConnectionCandidatePathRecord candidatePath));
            Assert.False(candidatePath.Validation.IsValidated);
            QuicS8P2PathValidationTestSupport.AssertSinglePathChallengeDatagram(
                receiveResult,
                preferredPath,
                runtime: runtime);

            QuicConnectionTransitionResult replyResult = runtime.Transition(
                new QuicConnectionConnectionCloseFrameReceivedEvent(
                    ObservedAtTicks: 40 + iteration,
                    QuicPathMigrationRecoveryTestSupport.CreateConnectionCloseMetadata()),
                nowTicks: 40 + iteration);

            Assert.True(replyResult.StateChanged);
            Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);
            Assert.Contains(replyResult.Effects, effect =>
                effect is QuicConnectionSendDatagramEffect send
                && send.PathIdentity == activePath);
            Assert.DoesNotContain(replyResult.Effects, effect =>
                effect is QuicConnectionSendDatagramEffect send
                && send.PathIdentity == preferredPath);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0541")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void PreferredAddressDiagnosticsFuzz_ClassifiesUnvalidatedPreferredAddressPacketsAsMigrationCandidates()
    {
        for (int iteration = 0; iteration < 6; iteration++)
        {
            QuicPreferredAddress preferredAddress = CreatePreferredAddress(iteration);
            QuicConnectionPathIdentity activePath = new($"203.0.113.{90 + iteration}", RemotePort: 443);
            QuicConnectionPathIdentity preferredPath = CreatePreferredPath(preferredAddress);
            QuicRecordingDiagnosticsSink diagnosticsSink = new();
            using QuicConnectionRuntime runtime =
                QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithOneRttKeysAndCommittedPeerTransportParameters(
                    activePath,
                    CreatePeerTransportParameters(preferredAddress),
                    diagnosticsSink);

            QuicConnectionTransitionResult result = runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: 20 + iteration,
                    preferredPath,
                    new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
                nowTicks: 20 + iteration);

            Assert.True(result.StateChanged);
            Assert.Contains(diagnosticsSink.Events, diagnosticEvent =>
                diagnosticEvent.Kind == QuicDiagnosticKind.AddressChangeClassified
                && diagnosticEvent.PathIdentity == preferredPath
                && diagnosticEvent.PathClassification == QuicConnectionPathClassification.MigrationCandidate);
            Assert.True(runtime.CandidatePaths.TryGetValue(preferredPath, out QuicConnectionCandidatePathRecord candidatePath));
            Assert.False(candidatePath.Validation.IsValidated);
            Assert.False(candidatePath.Validation.IsAbandoned);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0545")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void PreferredConnectionIdRoutingFuzz_RoutesPreferredConnectionIdAcrossPathMigrationUntilRetired()
    {
        for (int iteration = 0; iteration < 6; iteration++)
        {
            byte[] preferredConnectionId = [(byte)(0x30 + iteration), (byte)(0x40 + iteration), (byte)(0x50 + iteration)];
            using QuicConnectionRuntimeEndpoint endpoint = new(4);
            using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
            QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
            QuicConnectionPathIdentity activePath = new($"203.0.113.{110 + iteration}", $"198.51.100.{110 + iteration}", 443, 61234);
            QuicConnectionPathIdentity migratedPath = new($"203.0.113.{120 + iteration}", $"198.51.100.{120 + iteration}", 443, 61235);

            Assert.True(endpoint.TryRegisterConnection(handle, runtime));
            Assert.True(endpoint.TryUpdateEndpointBinding(handle, activePath));
            Assert.True(endpoint.TryRegisterConnectionId(handle, preferredConnectionId));
            Assert.True(endpoint.TryUpdateEndpointBinding(handle, migratedPath));

            QuicConnectionIngressResult routedResult = endpoint.ReceiveDatagram(
                QuicHeaderTestData.BuildShortHeader(0x00, [.. preferredConnectionId, 0xAA]),
                migratedPath);

            Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, routedResult.Disposition);
            Assert.Equal(handle, routedResult.Handle);

            Assert.True(endpoint.TryRetireConnectionId(handle, preferredConnectionId));

            QuicConnectionIngressResult retiredResult = endpoint.ReceiveDatagram(
                QuicHeaderTestData.BuildShortHeader(0x00, [.. preferredConnectionId, 0xBB]),
                migratedPath);

            Assert.Equal(QuicConnectionIngressDisposition.Unroutable, retiredResult.Disposition);
            Assert.Null(retiredResult.Handle);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0548")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void NoValidatedPathDiscardFuzz_DiscardsOnlyWhenNoValidatedPathRemains()
    {
        for (int iteration = 0; iteration < 6; iteration++)
        {
            QuicConnectionRuntime runtimeWithoutValidatedPath = QuicPathMigrationRecoveryTestSupport.CreateRuntime();
            QuicConnectionPathIdentity failedPath = new($"203.0.113.{140 + iteration}", RemotePort: 443);

            QuicConnectionTransitionResult discardResult = runtimeWithoutValidatedPath.Transition(
                new QuicConnectionPathValidationFailedEvent(
                    ObservedAtTicks: 20 + iteration,
                    failedPath,
                    IsAbandoned: true),
                nowTicks: 20 + iteration);

            Assert.True(discardResult.StateChanged);
            Assert.Equal(QuicConnectionPhase.Discarded, runtimeWithoutValidatedPath.Phase);
            Assert.Contains(discardResult.Effects, effect => effect is QuicConnectionDiscardConnectionStateEffect);

            QuicConnectionRuntime runtimeWithValidatedPath = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(
                new QuicConnectionPathIdentity($"203.0.113.{150 + iteration}", RemotePort: 443));
            QuicConnectionPathIdentity validatedPath = new($"203.0.113.{160 + iteration}", RemotePort: 443);
            Assert.True(runtimeWithValidatedPath.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: 30 + iteration,
                    validatedPath,
                    new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
                nowTicks: 30 + iteration).StateChanged);
            Assert.True(QuicPathMigrationRecoveryTestSupport.ValidatePath(
                runtimeWithValidatedPath,
                validatedPath,
                observedAtTicks: 40 + iteration).StateChanged);

            QuicConnectionTransitionResult retainedResult = runtimeWithValidatedPath.Transition(
                new QuicConnectionPathValidationFailedEvent(
                    ObservedAtTicks: 50 + iteration,
                    failedPath,
                    IsAbandoned: true),
                nowTicks: 50 + iteration);

            Assert.False(retainedResult.StateChanged);
            Assert.Equal(QuicConnectionPhase.Active, runtimeWithValidatedPath.Phase);
            Assert.True(runtimeWithValidatedPath.HasValidatedPath);
            Assert.DoesNotContain(retainedResult.Effects, effect => effect is QuicConnectionDiscardConnectionStateEffect);
        }
    }

    private static QuicTransportParameters CreatePeerTransportParameters(QuicPreferredAddress preferredAddress)
    {
        return new QuicTransportParameters
        {
            InitialSourceConnectionId = [0x10, 0x11, 0x12, 0x13],
            PreferredAddress = preferredAddress,
        };
    }

    private static QuicPreferredAddress CreatePreferredAddress(int iteration)
    {
        byte lowByte = (byte)(30 + iteration);
        return new QuicPreferredAddress
        {
            IPv4Address = [198, 51, 100, lowByte],
            IPv4Port = (ushort)(9443 + iteration),
            IPv6Address =
            [
                0x20, 0x01, 0x0D, 0xB8,
                0x00, 0x01, 0x00, 0x02,
                0x00, 0x03, 0x00, 0x04,
                0x00, 0x05, 0x00, lowByte,
            ],
            IPv6Port = (ushort)(9553 + iteration),
            ConnectionId = [(byte)(0x20 + iteration), (byte)(0x21 + iteration), (byte)(0x22 + iteration), (byte)(0x23 + iteration)],
            StatelessResetToken = Enumerable
                .Range(0, QuicPreferredAddressRequirementTestSupport.StatelessResetTokenLength)
                .Select(value => (byte)(0x40 + iteration + value))
                .ToArray(),
        };
    }

    private static QuicConnectionPathIdentity CreatePreferredPath(QuicPreferredAddress preferredAddress)
    {
        return new QuicConnectionPathIdentity(
            new IPAddress(preferredAddress.IPv4Address).ToString(),
            RemotePort: preferredAddress.IPv4Port);
    }
}
