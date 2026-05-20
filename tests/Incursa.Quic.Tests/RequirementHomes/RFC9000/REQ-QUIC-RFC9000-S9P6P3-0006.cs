using System.Net;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P6P3-0006")]
public sealed class REQ_QUIC_RFC9000_S9P6P3_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientMigratingToANewAddressUsesTheSameFamilyPreferredServerAddress()
    {
        byte[] initialSourceConnectionId = [0x10, 0x11, 0x12, 0x13];
        byte[] preferredConnectionId = [0x20, 0x21, 0x22, 0x23];
        byte[] statelessResetToken = [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F];
        byte[] preferredIpv4Address = [198, 51, 100, 43];
        byte[] preferredIpv6Address = [0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x2B];
        QuicTransportParameters transportParameters = new()
        {
            InitialSourceConnectionId = initialSourceConnectionId,
            PreferredAddress = new QuicPreferredAddress
            {
                IPv4Address = preferredIpv4Address,
                IPv4Port = 9451,
                IPv6Address = preferredIpv6Address,
                IPv6Port = 9561,
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

        QuicConnectionPathIdentity activeIpv4Path = new("203.0.113.43", "192.0.2.130", 443, 61264);
        QuicConnectionPathIdentity preferredIpv4Path = new(
            new IPAddress(preferredAddress.IPv4Address).ToString(),
            "192.0.2.131",
            preferredAddress.IPv4Port,
            61265);
        QuicConnectionPathIdentity activeIpv6Path = new("2001:db8:1:2:3:4:5:2a", "2001:db8:5:4:3:2:1:82", 443, 61266);
        QuicConnectionPathIdentity preferredIpv6Path = new(
            new IPAddress(preferredAddress.IPv6Address).ToString(),
            "2001:db8:5:4:3:2:1:83",
            preferredAddress.IPv6Port,
            61267);

        AssertMigratesToSameFamilyPreferredAddress(activeIpv4Path, preferredIpv4Path, preferredIpv6Path, parsedTransportParameters);
        AssertMigratesToSameFamilyPreferredAddress(activeIpv6Path, preferredIpv6Path, preferredIpv4Path, parsedTransportParameters);
    }

    private static void AssertMigratesToSameFamilyPreferredAddress(
        QuicConnectionPathIdentity activePath,
        QuicConnectionPathIdentity sameFamilyPreferredPath,
        QuicConnectionPathIdentity otherFamilyPreferredPath,
        QuicTransportParameters parsedTransportParameters)
    {
        using QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithOneRttKeysAndCommittedPeerTransportParameters(
            activePath,
            parsedTransportParameters);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        QuicConnectionTransitionResult discoveryResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                sameFamilyPreferredPath,
                datagram),
            nowTicks: 20);

        Assert.True(discoveryResult.StateChanged);
        Assert.True(runtime.CandidatePaths.TryGetValue(sameFamilyPreferredPath, out QuicConnectionCandidatePathRecord candidatePath));
        Assert.False(candidatePath.Validation.IsValidated);
        QuicS8P2PathValidationTestSupport.AssertSinglePathChallengeDatagram(
            discoveryResult,
            sameFamilyPreferredPath,
            runtime: runtime);
        Assert.False(runtime.CandidatePaths.ContainsKey(otherFamilyPreferredPath));
        Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);

        QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            sameFamilyPreferredPath,
            observedAtTicks: 30);

        Assert.True(validationResult.StateChanged);
        Assert.Equal(sameFamilyPreferredPath, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.ActivePath!.Value.IsValidated);
        Assert.DoesNotContain(runtime.CandidatePaths.Keys, path => EqualityComparer<QuicConnectionPathIdentity>.Default.Equals(path, otherFamilyPreferredPath));
        Assert.Contains(validationResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promote
            && promote.PathIdentity == sameFamilyPreferredPath
            && !promote.RestoreSavedState);
    }
}
