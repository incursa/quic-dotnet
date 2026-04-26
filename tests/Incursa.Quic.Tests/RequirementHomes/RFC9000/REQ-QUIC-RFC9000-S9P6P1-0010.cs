using System.Net;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P6P1-0010")]
public sealed class REQ_QUIC_RFC9000_S9P6P1_0010
{
    private static readonly QuicConnectionPathIdentity OriginalPath = new("203.0.113.10", RemotePort: 443);
    private static readonly byte[] InitialDestinationConnectionId = [0x10, 0x11, 0x12, 0x13];
    private static readonly byte[] InitialSourceConnectionId = [0x14, 0x15, 0x16, 0x17];
    private static readonly byte[] PreferredConnectionId = [0x20, 0x21, 0x22, 0x23];
    private static readonly byte[] PeerIssuedConnectionId = [0x30, 0x31, 0x32, 0x33];
    private static readonly byte[] PreferredIpv4Address = [198, 51, 100, 24];
    private static readonly byte[] PreferredIpv6Address =
    [
        0x20, 0x01, 0x0D, 0xB8,
        0x00, 0x01, 0x00, 0x02,
        0x00, 0x03, 0x00, 0x04,
        0x00, 0x05, 0x00, 0x18,
    ];
    private static readonly byte[] PreferredStatelessResetToken =
    [
        0x40, 0x41, 0x42, 0x43,
        0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4A, 0x4B,
        0x4C, 0x4D, 0x4E, 0x4F,
    ];

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientBeginsSendingFuturePacketsToThePreferredAddressAfterValidationSucceeds()
    {
        using QuicConnectionRuntime runtime = CreateRuntime();
        QuicConnectionPathIdentity preferredPath = CreatePreferredPath();
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
        Assert.True(runtime.CurrentPeerDestinationConnectionId.Span.SequenceEqual(InitialDestinationConnectionId));

        QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            preferredPath,
            observedAtTicks: 30);

        Assert.True(validationResult.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(preferredPath, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.CurrentPeerDestinationConnectionId.Span.SequenceEqual(PreferredConnectionId));
        Assert.False(runtime.CurrentPeerDestinationConnectionId.Span.SequenceEqual(InitialDestinationConnectionId));

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

        Assert.True(protectedPacket.Length > 1 + PreferredConnectionId.Length);
        Assert.True(protectedPacket.AsSpan(1, PreferredConnectionId.Length).SequenceEqual(PreferredConnectionId));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClientKeepsUsingTheOriginalServerAddressWhilePreferredAddressValidationIsPending()
    {
        using QuicConnectionRuntime runtime = CreateRuntime();
        QuicConnectionPathIdentity preferredPath = CreatePreferredPath();
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
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(OriginalPath, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.CurrentPeerDestinationConnectionId.Span.SequenceEqual(InitialDestinationConnectionId));
        Assert.False(runtime.CurrentPeerDestinationConnectionId.Span.SequenceEqual(PreferredConnectionId));

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

        Assert.True(protectedPacket.Length > 1 + InitialDestinationConnectionId.Length);
        Assert.True(protectedPacket.AsSpan(1, InitialDestinationConnectionId.Length).SequenceEqual(InitialDestinationConnectionId));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ClientKeepsThePeerIssuedConnectionIdWhenPreferredAddressValidationCompletesAfterANewConnectionIdArrival()
    {
        using QuicConnectionRuntime runtime = CreateRuntime();
        QuicConnectionPathIdentity preferredPath = CreatePreferredPath();
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
        Assert.True(runtime.CurrentPeerDestinationConnectionId.Span.SequenceEqual(InitialDestinationConnectionId));

        QuicConnectionTransitionResult newConnectionIdResult = ReceiveNewConnectionIdFrame(
            runtime,
            sequenceNumber: 1,
            retirePriorTo: 0,
            connectionId: PeerIssuedConnectionId,
            statelessResetToken: PreferredStatelessResetToken,
            observedAtTicks: 25);

        Assert.True(newConnectionIdResult.StateChanged);
        Assert.True(runtime.CurrentPeerDestinationConnectionId.Span.SequenceEqual(PeerIssuedConnectionId));

        QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            preferredPath,
            observedAtTicks: 30);

        Assert.True(validationResult.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(preferredPath, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.CurrentPeerDestinationConnectionId.Span.SequenceEqual(PeerIssuedConnectionId));
        Assert.False(runtime.CurrentPeerDestinationConnectionId.Span.SequenceEqual(PreferredConnectionId));

        Assert.True(runtime.TlsState.OneRttProtectPacketProtectionMaterial.HasValue);
        QuicHandshakeFlowCoordinator coordinator = new(
            runtime.CurrentPeerDestinationConnectionId,
            runtime.CurrentHandshakeSourceConnectionId);
        byte[] payload =
        [
            0x61, 0x62, 0x63, 0x64,
        ];

        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            payload,
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            runtime.TlsState.CurrentOneRttKeyPhaseBit,
            out byte[] protectedPacket));

        Assert.True(protectedPacket.Length > 1 + PeerIssuedConnectionId.Length);
        Assert.True(protectedPacket.AsSpan(1, PeerIssuedConnectionId.Length).SequenceEqual(PeerIssuedConnectionId));
    }

    private static QuicConnectionRuntime CreateRuntime()
    {
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(OriginalPath);
        Assert.True(runtime.TrySetHandshakeDestinationConnectionId(InitialDestinationConnectionId));
        Assert.True(runtime.TrySetHandshakeSourceConnectionId(InitialSourceConnectionId));
        QuicPathMigrationRecoveryTestSupport.CommitPeerTransportParametersAndSeedOneRttPacketProtectionMaterial(
            runtime,
            CreatePeerTransportParameters());
        return runtime;
    }

    private static QuicConnectionPathIdentity CreatePreferredPath()
    {
        return new QuicConnectionPathIdentity(
            new IPAddress(PreferredIpv4Address).ToString(),
            RemotePort: 9444);
    }

    private static QuicTransportParameters CreatePeerTransportParameters()
    {
        return new QuicTransportParameters
        {
            InitialSourceConnectionId = InitialSourceConnectionId,
            PreferredAddress = new QuicPreferredAddress
            {
                IPv4Address = PreferredIpv4Address,
                IPv4Port = 9444,
                IPv6Address = PreferredIpv6Address,
                IPv6Port = 9554,
                ConnectionId = PreferredConnectionId,
                StatelessResetToken = PreferredStatelessResetToken,
            },
        };
    }

    private static QuicConnectionTransitionResult ReceiveNewConnectionIdFrame(
        QuicConnectionRuntime runtime,
        ulong sequenceNumber,
        ulong retirePriorTo,
        ReadOnlySpan<byte> connectionId,
        ReadOnlySpan<byte> statelessResetToken,
        long observedAtTicks)
    {
        byte[] payload = QuicFrameTestData.BuildNewConnectionIdFrame(new QuicNewConnectionIdFrame(
            sequenceNumber,
            retirePriorTo,
            connectionId,
            statelessResetToken));

        Assert.True(runtime.TlsState.OneRttOpenPacketProtectionMaterial.HasValue);
        QuicHandshakeFlowCoordinator coordinator = new(
            runtime.CurrentPeerDestinationConnectionId,
            runtime.CurrentHandshakeSourceConnectionId);
        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            payload,
            runtime.TlsState.OneRttOpenPacketProtectionMaterial.Value,
            keyPhase: false,
            out byte[] protectedPacket));

        return runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: observedAtTicks,
                runtime.ActivePath!.Value.Identity,
                protectedPacket),
            nowTicks: observedAtTicks);
    }
}
