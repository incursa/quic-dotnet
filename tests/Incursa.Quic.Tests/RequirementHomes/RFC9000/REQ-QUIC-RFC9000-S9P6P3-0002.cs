using System.Net;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P6P3-0002")]
public sealed class REQ_QUIC_RFC9000_S9P6P3_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PreferredAddressValidationAbandonsTheOriginalServerAddressCandidateBeforePromoting()
    {
        byte[] initialSourceConnectionId = [0x10, 0x11, 0x12, 0x13];
        byte[] preferredConnectionId = [0x20, 0x21, 0x22, 0x23];
        byte[] statelessResetToken = [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F];
        byte[] preferredIpv4Address = [198, 51, 100, 41];
        byte[] preferredIpv6Address = [0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x29];
        QuicTransportParameters transportParameters = new()
        {
            InitialSourceConnectionId = initialSourceConnectionId,
            PreferredAddress = new QuicPreferredAddress
            {
                IPv4Address = preferredIpv4Address,
                IPv4Port = 9449,
                IPv6Address = preferredIpv6Address,
                IPv6Port = 9559,
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

        QuicConnectionPathIdentity activePath = new("203.0.113.41", "192.0.2.110", 443, 61244);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(activePath);
        QuicPathMigrationRecoveryTestSupport.CommitPeerTransportParameters(runtime, parsedTransportParameters);

        QuicConnectionPathIdentity originalValidationPath = new("203.0.113.41", "192.0.2.111", 443, 61245);
        QuicConnectionPathIdentity preferredValidationPath = new(
            new IPAddress(preferredAddress.IPv4Address).ToString(),
            "192.0.2.111",
            preferredAddress.IPv4Port,
            61245);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                originalValidationPath,
                datagram),
            nowTicks: 20).StateChanged);
        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 21,
                preferredValidationPath,
                datagram),
            nowTicks: 21).StateChanged);

        QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            preferredValidationPath,
            observedAtTicks: 30);

        Assert.True(validationResult.StateChanged);
        Assert.Contains(validationResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promote
            && promote.PathIdentity == preferredValidationPath
            && !promote.RestoreSavedState);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(preferredValidationPath, runtime.ActivePath!.Value.Identity);
        Assert.Equal(preferredValidationPath.RemoteAddress, runtime.LastValidatedRemoteAddress);
        Assert.False(runtime.CandidatePaths.ContainsKey(preferredValidationPath));
        Assert.True(runtime.RecentlyValidatedPaths.ContainsKey(preferredValidationPath));
        Assert.True(runtime.CandidatePaths.TryGetValue(originalValidationPath, out QuicConnectionCandidatePathRecord originalCandidatePath));
        Assert.True(originalCandidatePath.Validation.IsAbandoned);
        Assert.False(originalCandidatePath.Validation.IsValidated);
        Assert.Null(originalCandidatePath.Validation.ValidationDeadlineTicks);
    }
}
