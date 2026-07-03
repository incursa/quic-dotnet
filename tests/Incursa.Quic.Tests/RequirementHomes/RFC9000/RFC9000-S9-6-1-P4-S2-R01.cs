// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S9-6-1-P4-S2-R01")]
public sealed class REQ_QUIC_RFC9000_S9P6P1_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientSendsFuturePacketsToOriginalServerAddressAfterPreferredAddressValidationFails()
    {
        using QuicConnectionRuntime runtime = QuicS9P6P1PreferredAddressTestSupport.CreateClientRuntime(
            QuicS9P6P1PreferredAddressTestSupport.OriginalIpv4Path,
            QuicS9P6P1PreferredAddressTestSupport.CreatePreferredAddress());
        QuicConnectionPathIdentity preferredPath = QuicS9P6P1PreferredAddressTestSupport.CreatePreferredPath();

        QuicS9P6P1PreferredAddressTestSupport.ConfirmHandshake(runtime, observedAtTicks: 20);
        QuicConnectionTransitionResult failureResult = runtime.Transition(
            new QuicConnectionPathValidationFailedEvent(
                ObservedAtTicks: 30,
                preferredPath,
                IsAbandoned: true),
            nowTicks: 30);

        Assert.True(failureResult.StateChanged);
        Assert.Equal(QuicS9P6P1PreferredAddressTestSupport.OriginalIpv4Path, runtime.ActivePath!.Value.Identity);
        AssertFailedPreferredAddressCandidate(runtime, preferredPath);
        Assert.DoesNotContain(failureResult.Effects, effect => effect is QuicConnectionPromoteActivePathEffect);

        QuicConnectionTransitionResult closeResult = runtime.Transition(
            new QuicConnectionConnectionCloseFrameReceivedEvent(
                ObservedAtTicks: 40,
                QuicPathMigrationRecoveryTestSupport.CreateConnectionCloseMetadata()),
            nowTicks: 40);

        Assert.True(closeResult.StateChanged);
        Assert.Contains(closeResult.Effects, effect =>
            effect is QuicConnectionSendDatagramEffect send
            && send.PathIdentity == QuicS9P6P1PreferredAddressTestSupport.OriginalIpv4Path);
        Assert.DoesNotContain(closeResult.Effects, effect =>
            effect is QuicConnectionSendDatagramEffect send
            && send.PathIdentity == preferredPath);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClientKeepsUsingTheOriginalServerAddressWhenPreferredAddressValidationFails()
    {
        byte[] initialSourceConnectionId = [0x40, 0x41, 0x42, 0x43];
        byte[] preferredConnectionId = [0x50, 0x51, 0x52, 0x53];
        byte[] statelessResetToken = [0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F];
        byte[] preferredIpv4Address = [198, 51, 100, 21];
        byte[] preferredIpv6Address = [0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x07];
        QuicTransportParameters transportParameters = new()
        {
            InitialSourceConnectionId = initialSourceConnectionId,
            PreferredAddress = new QuicPreferredAddress
            {
                IPv4Address = preferredIpv4Address,
                IPv4Port = 9444,
                IPv6Address = preferredIpv6Address,
                IPv6Port = 9554,
                ConnectionId = preferredConnectionId,
                StatelessResetToken = statelessResetToken,
            },
        };

        Span<byte> destination = stackalloc byte[256];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            transportParameters,
            QuicTransportParameterRole.Server,
            destination,
            out int bytesWritten));

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            destination[..bytesWritten],
            QuicTransportParameterRole.Client,
            out QuicTransportParameters parsedTransportParameters));

        Assert.NotNull(parsedTransportParameters.PreferredAddress);
        QuicPreferredAddress preferredAddress = parsedTransportParameters.PreferredAddress!;

        QuicConnectionPathIdentity activePath = new("203.0.113.11", RemotePort: 443);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(activePath);

        QuicPathMigrationRecoveryTestSupport.CommitPeerTransportParameters(runtime, parsedTransportParameters);

        QuicConnectionPathIdentity preferredPath = new(
            new IPAddress(preferredAddress.IPv4Address).ToString(),
            RemotePort: preferredAddress.IPv4Port);
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
        Assert.False(candidatePath.Validation.IsAbandoned);

        QuicConnectionTransitionResult failureResult = runtime.Transition(
            new QuicConnectionPathValidationFailedEvent(
                ObservedAtTicks: 30,
                preferredPath,
                IsAbandoned: true),
            nowTicks: 30);

        Assert.True(failureResult.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);
        Assert.Null(runtime.LastValidatedRemoteAddress);
        Assert.True(runtime.CandidatePaths.TryGetValue(preferredPath, out candidatePath));
        Assert.True(candidatePath.Validation.IsAbandoned);
        Assert.False(candidatePath.Validation.IsValidated);
        Assert.DoesNotContain(failureResult.Effects, effect => effect is QuicConnectionPromoteActivePathEffect);
        Assert.False(runtime.RecentlyValidatedPaths.ContainsKey(preferredPath));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ClientSendsFuturePacketsToOriginalIpv6ServerAddressAfterIpv6PreferredAddressValidationFails()
    {
        using QuicConnectionRuntime runtime = QuicS9P6P1PreferredAddressTestSupport.CreateClientRuntime(
            QuicS9P6P1PreferredAddressTestSupport.OriginalIpv6Path,
            QuicS9P6P1PreferredAddressTestSupport.CreatePreferredAddress());
        QuicConnectionPathIdentity preferredPath = QuicS9P6P1PreferredAddressTestSupport.CreatePreferredPath(useIpv6: true);

        QuicS9P6P1PreferredAddressTestSupport.ConfirmHandshake(runtime, observedAtTicks: 20);
        QuicConnectionTransitionResult failureResult = runtime.Transition(
            new QuicConnectionPathValidationFailedEvent(
                ObservedAtTicks: 30,
                preferredPath,
                IsAbandoned: true),
            nowTicks: 30);

        Assert.True(failureResult.StateChanged);
        Assert.Equal(QuicS9P6P1PreferredAddressTestSupport.OriginalIpv6Path, runtime.ActivePath!.Value.Identity);
        AssertFailedPreferredAddressCandidate(runtime, preferredPath);

        QuicConnectionTransitionResult closeResult = runtime.Transition(
            new QuicConnectionConnectionCloseFrameReceivedEvent(
                ObservedAtTicks: 40,
                QuicPathMigrationRecoveryTestSupport.CreateConnectionCloseMetadata()),
            nowTicks: 40);

        Assert.True(closeResult.StateChanged);
        Assert.Contains(closeResult.Effects, effect =>
            effect is QuicConnectionSendDatagramEffect send
            && send.PathIdentity == QuicS9P6P1PreferredAddressTestSupport.OriginalIpv6Path);
        Assert.DoesNotContain(closeResult.Effects, effect =>
            effect is QuicConnectionSendDatagramEffect send
            && send.PathIdentity == preferredPath);
    }

    private static void AssertFailedPreferredAddressCandidate(
        QuicConnectionRuntime runtime,
        QuicConnectionPathIdentity preferredPath)
    {
        Assert.True(runtime.CandidatePaths.TryGetValue(preferredPath, out QuicConnectionCandidatePathRecord candidatePath));
        Assert.True(candidatePath.Validation.IsAbandoned);
        Assert.False(candidatePath.Validation.IsValidated);
        Assert.Null(candidatePath.Validation.ValidationDeadlineTicks);
        Assert.False(runtime.RecentlyValidatedPaths.ContainsKey(preferredPath));
    }
}
