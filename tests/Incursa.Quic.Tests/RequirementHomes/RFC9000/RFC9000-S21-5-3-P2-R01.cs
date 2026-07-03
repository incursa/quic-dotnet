// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S21-5-3-P2-R01")]
public sealed class REQ_QUIC_RFC9000_S21P5P3_0001
{
    [Fact]
    [Requirement("RFC9000-S21-5-3-P2-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientBeginsSendingNonProbingPacketsToThePreferredAddressAfterValidationSucceeds()
    {
        using QuicConnectionRuntime runtime = QuicS9P6P1PreferredAddressTestSupport.CreateClientRuntime(
            QuicS9P6P1PreferredAddressTestSupport.OriginalIpv4Path,
            QuicS9P6P1PreferredAddressTestSupport.CreatePreferredAddress());
        QuicConnectionPathIdentity preferredPath = QuicS9P6P1PreferredAddressTestSupport.CreatePreferredPath();
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        QuicConnectionTransitionResult receiveResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                preferredPath,
                datagram),
            nowTicks: 20);

        Assert.True(receiveResult.StateChanged);
        Assert.True(runtime.CandidatePaths.TryGetValue(preferredPath, out QuicConnectionCandidatePathRecord candidatePath));
        Assert.False(candidatePath.Validation.IsValidated);
        QuicS8P2PathValidationTestSupport.AssertSinglePathChallengeDatagram(
            receiveResult,
            preferredPath,
            runtime: runtime);

        QuicConnectionTransitionResult validationResult = QuicS9P6P1PreferredAddressTestSupport.ValidatePreferredPath(
            runtime,
            preferredPath,
            observedAtTicks: 30);

        Assert.True(validationResult.StateChanged);
        Assert.Contains(validationResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promoteActivePathEffect
            && promoteActivePathEffect.PathIdentity == preferredPath);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(preferredPath, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.CurrentPeerDestinationConnectionId.Span.SequenceEqual(
            QuicS9P6P1PreferredAddressTestSupport.PreferredConnectionId));

        Assert.True(runtime.TlsState.OneRttProtectPacketProtectionMaterial.HasValue);
        QuicHandshakeFlowCoordinator coordinator = new(
            runtime.CurrentPeerDestinationConnectionId,
            runtime.CurrentHandshakeSourceConnectionId);
        byte[] payload =
        [
            0x41, 0x42, 0x43, 0x44,
        ];

        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            payload,
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            runtime.TlsState.CurrentOneRttKeyPhaseBit,
            out byte[] protectedPacket));

        Assert.True(protectedPacket.Length > 1 + QuicS9P6P1PreferredAddressTestSupport.PreferredConnectionId.Length);
        Assert.True(protectedPacket.AsSpan(1, QuicS9P6P1PreferredAddressTestSupport.PreferredConnectionId.Length)
            .SequenceEqual(QuicS9P6P1PreferredAddressTestSupport.PreferredConnectionId));
    }

    [Fact]
    [Requirement("RFC9000-S21-5-3-P2-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClientKeepsSendingNonProbingPacketsToTheOriginalServerAddressWhilePreferredAddressValidationIsPending()
    {
        using QuicConnectionRuntime runtime = QuicS9P6P1PreferredAddressTestSupport.CreateClientRuntime(
            QuicS9P6P1PreferredAddressTestSupport.OriginalIpv4Path,
            QuicS9P6P1PreferredAddressTestSupport.CreatePreferredAddress());
        QuicConnectionPathIdentity preferredPath = QuicS9P6P1PreferredAddressTestSupport.CreatePreferredPath();
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        QuicConnectionTransitionResult receiveResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                preferredPath,
                datagram),
            nowTicks: 20);

        Assert.True(receiveResult.StateChanged);
        Assert.True(runtime.CandidatePaths.TryGetValue(preferredPath, out QuicConnectionCandidatePathRecord candidatePath));
        Assert.False(candidatePath.Validation.IsValidated);
        QuicS8P2PathValidationTestSupport.AssertSinglePathChallengeDatagram(
            receiveResult,
            preferredPath,
            runtime: runtime);
        Assert.DoesNotContain(receiveResult.Effects, effect =>
            effect is QuicConnectionSendDatagramEffect sendDatagramEffect
            && sendDatagramEffect.PathIdentity == preferredPath
            && !QuicS8P2PathValidationTestSupport.TryOpenPathChallengePayload(
                runtime,
                sendDatagramEffect.Datagram.Span,
                out _,
                out _,
                out _));
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(QuicS9P6P1PreferredAddressTestSupport.OriginalIpv4Path, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.CurrentPeerDestinationConnectionId.Span.SequenceEqual(
            QuicS9P6P1PreferredAddressTestSupport.InitialDestinationConnectionId));

        Assert.True(runtime.TlsState.OneRttProtectPacketProtectionMaterial.HasValue);
        QuicHandshakeFlowCoordinator coordinator = new(
            runtime.CurrentPeerDestinationConnectionId,
            runtime.CurrentHandshakeSourceConnectionId);
        byte[] payload =
        [
            0x51, 0x52, 0x53, 0x54,
        ];

        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            payload,
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            runtime.TlsState.CurrentOneRttKeyPhaseBit,
            out byte[] protectedPacket));

        Assert.True(protectedPacket.Length > 1 + QuicS9P6P1PreferredAddressTestSupport.InitialDestinationConnectionId.Length);
        Assert.True(protectedPacket.AsSpan(1, QuicS9P6P1PreferredAddressTestSupport.InitialDestinationConnectionId.Length)
            .SequenceEqual(QuicS9P6P1PreferredAddressTestSupport.InitialDestinationConnectionId));
    }
}
