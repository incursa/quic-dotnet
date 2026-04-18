using System.Net;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S18P2-0017")]
public sealed class REQ_QUIC_RFC9000_S18P2_0017
{
    private static readonly QuicConnectionPathIdentity OriginalPath = new("203.0.113.30", RemotePort: 443);
    private static readonly byte[] DedicatedAddressIpv4 = [198, 51, 100, 30];
    private static readonly byte[] PreferredConnectionId = [0x20, 0x21, 0x22, 0x23];
    private static readonly byte[] PreferredIpv6Address = [0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x1E];
    private static readonly byte[] StatelessResetToken = [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F];

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0017")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerKeepsTheOriginalAddressBeforePreferredAddressValidationCompletes()
    {
        QuicTransportParameters parsedTransportParameters = ParsePeerTransportParameters(
            CreatePeerTransportParameters(
                DedicatedAddressIpv4,
                preferredIpv4Port: 9443));

        using QuicConnectionRuntime runtime = CreateRuntime(parsedTransportParameters);
        Assert.True(runtime.TlsState.PeerTransportParameters!.DisableActiveMigration);

        QuicConnectionPathIdentity preferredPath = CreatePreferredPath(parsedTransportParameters.PreferredAddress!);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        QuicConnectionTransitionResult receiveResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                preferredPath,
                datagram),
            nowTicks: 20);

        Assert.True(receiveResult.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(OriginalPath, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.CandidatePaths.TryGetValue(preferredPath, out QuicConnectionCandidatePathRecord candidatePath));
        Assert.False(candidatePath.Validation.IsValidated);
        Assert.DoesNotContain(receiveResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promoteActivePathEffect
            && promoteActivePathEffect.PathIdentity == preferredPath);
    }

    private static QuicConnectionRuntime CreateRuntime(QuicTransportParameters peerTransportParameters)
    {
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(OriginalPath);
        QuicPathMigrationRecoveryTestSupport.CommitPeerTransportParameters(runtime, peerTransportParameters);
        return runtime;
    }

    private static QuicConnectionPathIdentity CreatePreferredPath(QuicPreferredAddress preferredAddress)
    {
        return new QuicConnectionPathIdentity(
            new IPAddress(preferredAddress.IPv4Address).ToString(),
            RemotePort: preferredAddress.IPv4Port);
    }

    private static QuicTransportParameters CreatePeerTransportParameters(
        byte[] preferredIpv4Address,
        ushort preferredIpv4Port)
    {
        return new QuicTransportParameters
        {
            InitialSourceConnectionId = [0x10, 0x11, 0x12, 0x13],
            DisableActiveMigration = true,
            PreferredAddress = new QuicPreferredAddress
            {
                IPv4Address = preferredIpv4Address,
                IPv4Port = preferredIpv4Port,
                IPv6Address = PreferredIpv6Address,
                IPv6Port = 9553,
                ConnectionId = PreferredConnectionId,
                StatelessResetToken = StatelessResetToken,
            },
        };
    }

    private static QuicTransportParameters ParsePeerTransportParameters(QuicTransportParameters transportParameters)
    {
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

        return parsedTransportParameters;
    }
}
