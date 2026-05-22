using System.Net;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0525")]
public sealed class REQ_QUIC_RFC9000_0525
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientChoosesThePreferredAddressAfterHandshakeConfirmationAndPromotesItWhenValidationSucceeds()
    {
        byte[] initialSourceConnectionId = [0x10, 0x11, 0x12, 0x13];
        byte[] preferredConnectionId = [0x20, 0x21, 0x22, 0x23];
        byte[] statelessResetToken = [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F];
        byte[] preferredIpv4Address = [198, 51, 100, 20];
        byte[] preferredIpv6Address = [0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06];
        QuicTransportParameters transportParameters = new()
        {
            InitialSourceConnectionId = initialSourceConnectionId,
            PreferredAddress = new QuicPreferredAddress
            {
                IPv4Address = preferredIpv4Address,
                IPv4Port = 9443,
                IPv6Address = preferredIpv6Address,
                IPv6Port = 9553,
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
        Assert.Equal(preferredIpv4Address, preferredAddress.IPv4Address);
        Assert.Equal(preferredIpv6Address, preferredAddress.IPv6Address);
        Assert.Equal(preferredConnectionId, preferredAddress.ConnectionId);
        Assert.Equal(statelessResetToken, preferredAddress.StatelessResetToken);

        QuicConnectionPathIdentity activePath = new("203.0.113.10", RemotePort: 443);
        QuicConnectionRuntime runtime = QuicS9P6P1PreferredAddressTestSupport.CreateClientRuntime(
            activePath,
            parsedTransportParameters.PreferredAddress);
        Assert.False(runtime.HandshakeConfirmed);

        QuicConnectionPathIdentity preferredPath = new(
            new IPAddress(preferredAddress.IPv4Address).ToString(),
            RemotePort: preferredAddress.IPv4Port);
        QuicConnectionTransitionResult handshakeResult = QuicS9P6P1PreferredAddressTestSupport.ConfirmHandshake(
            runtime,
            observedAtTicks: 20);

        Assert.True(handshakeResult.StateChanged);
        Assert.True(runtime.HandshakeConfirmed);
        Assert.Contains(handshakeResult.Effects, effect =>
            effect is QuicConnectionSendDatagramEffect sendDatagramEffect
            && sendDatagramEffect.PathIdentity == preferredPath);
        Assert.True(runtime.CandidatePaths.TryGetValue(preferredPath, out QuicConnectionCandidatePathRecord candidatePath));
        Assert.False(candidatePath.Validation.IsValidated);
        Assert.False(candidatePath.Validation.IsAbandoned);
        Assert.True(candidatePath.Validation.ChallengeSendCount > 0);

        QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            preferredPath,
            observedAtTicks: 30);

        Assert.True(validationResult.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(preferredPath, runtime.ActivePath!.Value.Identity);
        Assert.Equal(preferredPath.RemoteAddress, runtime.LastValidatedRemoteAddress);
        Assert.False(runtime.CandidatePaths.ContainsKey(preferredPath));
        Assert.True(runtime.RecentlyValidatedPaths.ContainsKey(preferredPath));
        Assert.Contains(validationResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promoteActivePathEffect
            && promoteActivePathEffect.PathIdentity == preferredPath
            && !promoteActivePathEffect.RestoreSavedState);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClientDoesNotChooseThePreferredAddressBeforeHandshakeConfirmation()
    {
        using QuicConnectionRuntime runtime = QuicS9P6P1PreferredAddressTestSupport.CreateClientRuntime(
            QuicS9P6P1PreferredAddressTestSupport.OriginalIpv4Path,
            QuicS9P6P1PreferredAddressTestSupport.CreatePreferredAddress());
        QuicConnectionPathIdentity preferredPath = QuicS9P6P1PreferredAddressTestSupport.CreatePreferredPath();

        Assert.False(runtime.HandshakeConfirmed);
        Assert.Equal(QuicS9P6P1PreferredAddressTestSupport.OriginalIpv4Path, runtime.ActivePath!.Value.Identity);
        Assert.False(runtime.CandidatePaths.ContainsKey(preferredPath));
        Assert.False(runtime.RecentlyValidatedPaths.ContainsKey(preferredPath));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ClientChoosesIpv6WhenTheIpv4PreferredAddressFamilyIsUnused()
    {
        byte[] unusedIpv4Address = [0, 0, 0, 0];
        using QuicConnectionRuntime runtime = QuicS9P6P1PreferredAddressTestSupport.CreateClientRuntime(
            QuicS9P6P1PreferredAddressTestSupport.OriginalIpv4Path,
            QuicS9P6P1PreferredAddressTestSupport.CreatePreferredAddress(
                ipv4Address: unusedIpv4Address,
                ipv4Port: 0));
        QuicConnectionPathIdentity preferredPath = QuicS9P6P1PreferredAddressTestSupport.CreatePreferredPath(useIpv6: true);

        QuicConnectionTransitionResult result = QuicS9P6P1PreferredAddressTestSupport.ConfirmHandshake(
            runtime,
            observedAtTicks: 20);

        Assert.True(result.StateChanged);
        Assert.False(runtime.CandidatePaths.ContainsKey(QuicS9P6P1PreferredAddressTestSupport.CreatePreferredPath()));
        QuicS9P6P1PreferredAddressTestSupport.AssertCandidatePathPendingValidation(runtime, preferredPath);
        QuicS9P6P1PreferredAddressTestSupport.AssertPathChallengeSent(runtime, result, preferredPath);
    }
}

