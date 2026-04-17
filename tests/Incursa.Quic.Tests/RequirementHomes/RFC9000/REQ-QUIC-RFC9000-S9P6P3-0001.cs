using System.Net;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P6P3-0001")]
public sealed class REQ_QUIC_RFC9000_S9P6P3_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientPerformsConcurrentValidationToTheOriginalAndPreferredServerAddressesFromItsNewAddress()
    {
        byte[] initialSourceConnectionId = [0x10, 0x11, 0x12, 0x13];
        byte[] preferredConnectionId = [0x20, 0x21, 0x22, 0x23];
        byte[] statelessResetToken = [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F];
        byte[] preferredIpv4Address = [198, 51, 100, 40];
        byte[] preferredIpv6Address = [0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x28];
        QuicTransportParameters transportParameters = new()
        {
            InitialSourceConnectionId = initialSourceConnectionId,
            PreferredAddress = new QuicPreferredAddress
            {
                IPv4Address = preferredIpv4Address,
                IPv4Port = 9448,
                IPv6Address = preferredIpv6Address,
                IPv6Port = 9558,
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

        QuicConnectionPathIdentity activePath = new("203.0.113.40", "192.0.2.100", 443, 61234);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(activePath);
        QuicPathMigrationRecoveryTestSupport.CommitPeerTransportParameters(runtime, parsedTransportParameters);

        QuicConnectionPathIdentity originalValidationPath = new("203.0.113.40", "192.0.2.101", 443, 61235);
        QuicConnectionPathIdentity preferredValidationPath = new(
            new IPAddress(preferredAddress.IPv4Address).ToString(),
            "192.0.2.101",
            preferredAddress.IPv4Port,
            61235);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        QuicConnectionTransitionResult originalReceiveResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                originalValidationPath,
                datagram),
            nowTicks: 20);

        Assert.True(originalReceiveResult.StateChanged);
        Assert.Contains(originalReceiveResult.Effects, effect =>
            effect is QuicConnectionSendDatagramEffect sendDatagramEffect
            && sendDatagramEffect.PathIdentity == originalValidationPath
            && QuicFrameCodec.TryParsePathChallengeFrame(sendDatagramEffect.Datagram.Span, out _, out _));
        Assert.True(runtime.CandidatePaths.TryGetValue(originalValidationPath, out QuicConnectionCandidatePathRecord originalCandidatePath));
        Assert.False(originalCandidatePath.Validation.IsValidated);
        Assert.False(originalCandidatePath.Validation.IsAbandoned);
        Assert.Equal(1UL, originalCandidatePath.Validation.ChallengeSendCount);

        QuicConnectionTransitionResult preferredReceiveResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 21,
                preferredValidationPath,
                datagram),
            nowTicks: 21);

        Assert.True(preferredReceiveResult.StateChanged);
        Assert.Contains(preferredReceiveResult.Effects, effect =>
            effect is QuicConnectionSendDatagramEffect sendDatagramEffect
            && sendDatagramEffect.PathIdentity == preferredValidationPath
            && QuicFrameCodec.TryParsePathChallengeFrame(sendDatagramEffect.Datagram.Span, out _, out _));
        Assert.True(runtime.CandidatePaths.TryGetValue(preferredValidationPath, out QuicConnectionCandidatePathRecord preferredCandidatePath));
        Assert.False(preferredCandidatePath.Validation.IsValidated);
        Assert.False(preferredCandidatePath.Validation.IsAbandoned);
        Assert.Equal(1UL, preferredCandidatePath.Validation.ChallengeSendCount);

        Assert.Equal(2, runtime.CandidatePaths.Count);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);
    }
}
