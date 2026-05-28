// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic.Tests;

internal static class QuicS9P6P1PreferredAddressTestSupport
{
    internal static readonly QuicConnectionPathIdentity OriginalIpv4Path = new("203.0.113.10", RemotePort: 443);
    internal static readonly QuicConnectionPathIdentity OriginalIpv6Path = new("2001:db8:1::10", RemotePort: 443);
    internal static readonly byte[] InitialDestinationConnectionId = [0x10, 0x11, 0x12, 0x13];
    internal static readonly byte[] InitialSourceConnectionId = [0x14, 0x15, 0x16, 0x17];
    internal static readonly byte[] PreferredConnectionId = [0x20, 0x21, 0x22, 0x23];
    internal static readonly byte[] PreferredIpv4Address = [198, 51, 100, 24];
    internal static readonly byte[] PreferredIpv6Address =
    [
        0x20, 0x01, 0x0D, 0xB8,
        0x00, 0x01, 0x00, 0x02,
        0x00, 0x03, 0x00, 0x04,
        0x00, 0x05, 0x00, 0x18,
    ];
    internal static readonly byte[] PreferredStatelessResetToken =
    [
        0x40, 0x41, 0x42, 0x43,
        0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4A, 0x4B,
        0x4C, 0x4D, 0x4E, 0x4F,
    ];

    internal static QuicConnectionRuntime CreateClientRuntime(
        QuicConnectionPathIdentity activePath,
        QuicPreferredAddress? preferredAddress = null)
    {
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePathBeforeHandshakeConfirmation(activePath);
        Assert.True(runtime.TrySetHandshakeDestinationConnectionId(InitialDestinationConnectionId));
        Assert.True(runtime.TrySetHandshakeSourceConnectionId(InitialSourceConnectionId));
        QuicPathMigrationRecoveryTestSupport.CommitPeerTransportParametersAndSeedOneRttPacketProtectionMaterial(
            runtime,
            CreatePeerTransportParameters(preferredAddress));

        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.True(runtime.PeerHandshakeTranscriptCompleted);
        Assert.False(runtime.HandshakeConfirmed);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);
        return runtime;
    }

    internal static QuicConnectionRuntime CreateConfirmedClientRuntime(
        QuicConnectionPathIdentity activePath,
        QuicPreferredAddress? preferredAddress = null)
    {
        QuicConnectionRuntime runtime = CreateClientRuntime(activePath, preferredAddress);
        ConfirmHandshake(runtime, observedAtTicks: 3);
        return runtime;
    }

    internal static QuicConnectionTransitionResult ConfirmHandshake(QuicConnectionRuntime runtime, long observedAtTicks)
    {
        QuicConnectionTransitionResult result = QuicPostHandshakeTicketTestSupport.ReceiveProtectedHandshakeDonePacket(
            runtime,
            observedAtTicks);

        Assert.True(runtime.HandshakeConfirmed);
        return result;
    }

    internal static QuicPreferredAddress CreatePreferredAddress(
        byte[]? ipv4Address = null,
        ushort ipv4Port = 9444,
        byte[]? ipv6Address = null,
        ushort ipv6Port = 9554)
    {
        return new QuicPreferredAddress
        {
            IPv4Address = (ipv4Address ?? PreferredIpv4Address).ToArray(),
            IPv4Port = ipv4Port,
            IPv6Address = (ipv6Address ?? PreferredIpv6Address).ToArray(),
            IPv6Port = ipv6Port,
            ConnectionId = PreferredConnectionId.ToArray(),
            StatelessResetToken = PreferredStatelessResetToken.ToArray(),
        };
    }

    internal static QuicConnectionPathIdentity CreatePreferredPath(bool useIpv6 = false)
    {
        return new QuicConnectionPathIdentity(
            new IPAddress(useIpv6 ? PreferredIpv6Address : PreferredIpv4Address).ToString(),
            RemotePort: useIpv6 ? 9554 : 9444);
    }

    internal static void AssertPathChallengeSent(
        QuicConnectionRuntime runtime,
        QuicConnectionTransitionResult result,
        QuicConnectionPathIdentity pathIdentity)
    {
        Assert.Contains(result.Effects, effect =>
            effect is QuicConnectionSendDatagramEffect send
            && send.PathIdentity == pathIdentity
            && QuicS8P2PathValidationTestSupport.TryOpenPathChallengePayload(
                runtime,
                send.Datagram.Span,
                out _,
                out _,
                out _));
    }

    internal static void AssertNoPathChallengeSent(
        QuicConnectionTransitionResult result)
    {
        Assert.DoesNotContain(result.Effects, effect =>
            effect is QuicConnectionSendDatagramEffect send
            && QuicFrameCodec.TryParsePathChallengeFrame(send.Datagram.Span, out _, out _));
    }

    internal static void AssertCandidatePathPendingValidation(
        QuicConnectionRuntime runtime,
        QuicConnectionPathIdentity pathIdentity)
    {
        Assert.True(runtime.CandidatePaths.TryGetValue(pathIdentity, out QuicConnectionCandidatePathRecord candidatePath));
        Assert.False(candidatePath.Validation.IsValidated);
        Assert.False(candidatePath.Validation.IsAbandoned);
        Assert.True(candidatePath.Validation.ChallengeSendCount > 0);
        Assert.True(candidatePath.Validation.ValidationDeadlineTicks.HasValue);
    }

    internal static QuicConnectionTransitionResult ValidatePreferredPath(
        QuicConnectionRuntime runtime,
        QuicConnectionPathIdentity preferredPath,
        long observedAtTicks)
    {
        QuicConnectionTransitionResult result = QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            preferredPath,
            observedAtTicks);

        Assert.True(result.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(preferredPath, runtime.ActivePath!.Value.Identity);
        Assert.False(runtime.CandidatePaths.ContainsKey(preferredPath));
        Assert.True(runtime.RecentlyValidatedPaths.ContainsKey(preferredPath));
        return result;
    }

    private static QuicTransportParameters CreatePeerTransportParameters(QuicPreferredAddress? preferredAddress)
    {
        return new QuicTransportParameters
        {
            InitialSourceConnectionId = InitialSourceConnectionId.ToArray(),
            PreferredAddress = preferredAddress,
        };
    }
}
