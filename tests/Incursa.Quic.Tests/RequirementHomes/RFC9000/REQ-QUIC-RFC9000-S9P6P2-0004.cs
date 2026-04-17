using System.Net;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P6P2-0004")]
public sealed class REQ_QUIC_RFC9000_S9P6P2_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void OldAddressPacketsDoNotRevertTheConnectionAfterPreferredAddressValidationCompletes()
    {
        byte[] initialSourceConnectionId = [0x40, 0x41, 0x42, 0x43];
        byte[] preferredConnectionId = [0x50, 0x51, 0x52, 0x53];
        byte[] statelessResetToken = [0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F];
        byte[] preferredIpv4Address = [198, 51, 100, 40];
        byte[] preferredIpv6Address = [0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x28];
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

        QuicConnectionPathIdentity activePath = new("203.0.113.40", RemotePort: 443);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(activePath);
        QuicPathMigrationRecoveryTestSupport.CommitPeerTransportParameters(runtime, parsedTransportParameters);

        QuicConnectionPathIdentity preferredPath = new(
            new IPAddress(preferredAddress.IPv4Address).ToString(),
            RemotePort: preferredAddress.IPv4Port);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                preferredPath,
                datagram),
            nowTicks: 20).StateChanged);

        QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            preferredPath,
            observedAtTicks: 30);

        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(preferredPath, runtime.ActivePath!.Value.Identity);

        QuicConnectionTransitionResult oldAddressResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 40,
                activePath,
                datagram),
            nowTicks: 40);

        Assert.False(oldAddressResult.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(preferredPath, runtime.ActivePath!.Value.Identity);
        Assert.False(runtime.CandidatePaths.ContainsKey(activePath));
        Assert.DoesNotContain(oldAddressResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promoteActivePathEffect
            && promoteActivePathEffect.PathIdentity == activePath);
    }
}
