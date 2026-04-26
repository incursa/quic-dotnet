using System.Net;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P6P1-0009")]
public sealed class REQ_QUIC_RFC9000_S9P6P1_0009
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientUsesThePreferredAddressConnectionIdAfterPreferredAddressValidationSucceeds(bool useIpv6)
    {
        byte[] initialDestinationConnectionId = [0x10, 0x11, 0x12, 0x13];
        byte[] initialSourceConnectionId = [0x14, 0x15, 0x16, 0x17];
        byte[] preferredConnectionId = [0x20, 0x21, 0x22, 0x23];
        byte[] statelessResetToken =
        [
            0x30, 0x31, 0x32, 0x33,
            0x34, 0x35, 0x36, 0x37,
            0x38, 0x39, 0x3A, 0x3B,
            0x3C, 0x3D, 0x3E, 0x3F,
        ];
        byte[] preferredIpv4Address = [198, 51, 100, 24];
        byte[] preferredIpv6Address =
        [
            0x20, 0x01, 0x0D, 0xB8,
            0x00, 0x01, 0x00, 0x02,
            0x00, 0x03, 0x00, 0x04,
            0x00, 0x05, 0x00, 0x18,
        ];
        ushort preferredIpv4Port = 9444;
        ushort preferredIpv6Port = 9554;

        QuicTransportParameters peerTransportParameters = new()
        {
            InitialSourceConnectionId = initialSourceConnectionId,
            PreferredAddress = new QuicPreferredAddress
            {
                IPv4Address = preferredIpv4Address,
                IPv4Port = preferredIpv4Port,
                IPv6Address = preferredIpv6Address,
                IPv6Port = preferredIpv6Port,
                ConnectionId = preferredConnectionId,
                StatelessResetToken = statelessResetToken,
            },
        };

        byte[] preferredAddressBytes = useIpv6 ? preferredIpv6Address : preferredIpv4Address;
        ushort preferredAddressPort = useIpv6 ? preferredIpv6Port : preferredIpv4Port;

        QuicConnectionPathIdentity activePath = new("203.0.113.10", RemotePort: 443);
        using QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(activePath);
        Assert.True(runtime.TrySetHandshakeDestinationConnectionId(initialDestinationConnectionId));
        Assert.True(runtime.TrySetHandshakeSourceConnectionId(initialSourceConnectionId));
        QuicPathMigrationRecoveryTestSupport.CommitPeerTransportParametersAndSeedOneRttPacketProtectionMaterial(
            runtime,
            peerTransportParameters);

        QuicConnectionPathIdentity preferredPath = new(
            new IPAddress(preferredAddressBytes).ToString(),
            RemotePort: preferredAddressPort);
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

        QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            preferredPath,
            observedAtTicks: 30);

        Assert.True(validationResult.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(preferredPath, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.CurrentPeerDestinationConnectionId.Span.SequenceEqual(preferredConnectionId));

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

        Assert.True(protectedPacket.Length > 1 + preferredConnectionId.Length);
        Assert.True(protectedPacket.AsSpan(1, preferredConnectionId.Length).SequenceEqual(preferredConnectionId));
    }
}
