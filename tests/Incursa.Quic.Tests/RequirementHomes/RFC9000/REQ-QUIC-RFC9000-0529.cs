using System.Net;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0529")]
public sealed class REQ_QUIC_RFC9000_0529
{
    private static readonly QuicConnectionPathIdentity OriginalPath = new("203.0.113.68", RemotePort: 443);
    private static readonly byte[] InitialSourceConnectionId = [0x10, 0x11, 0x12, 0x13];
    private static readonly byte[] PreferredConnectionId = [0x20, 0x21, 0x22, 0x23];
    private static readonly byte[] PreferredIpv4Address = [198, 51, 100, 68];
    private static readonly byte[] PreferredIpv6Address =
    [
        0x20, 0x01, 0x0D, 0xB8,
        0x00, 0x01, 0x00, 0x02,
        0x00, 0x03, 0x00, 0x04,
        0x00, 0x05, 0x00, 0x44,
    ];
    private static readonly byte[] PreferredStatelessResetToken =
    [
        0x30, 0x31, 0x32, 0x33,
        0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3A, 0x3B,
        0x3C, 0x3D, 0x3E, 0x3F,
    ];
    private static readonly QuicConnectionPathIdentity PreferredPath = new(
        new IPAddress(PreferredIpv4Address).ToString(),
        RemotePort: 9468);

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0529")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientValidatesTheChosenPreferredAddressBeforeMigration()
    {
        using QuicConnectionRuntime runtime = CreateRuntime();

        QuicConnectionTransitionResult discoveryResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                PreferredPath,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 20);

        Assert.True(discoveryResult.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(OriginalPath, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.CandidatePaths.TryGetValue(PreferredPath, out QuicConnectionCandidatePathRecord candidatePath));
        Assert.False(candidatePath.Validation.IsValidated);
        QuicS8P2PathValidationTestSupport.AssertSinglePathChallengeDatagram(
            discoveryResult,
            PreferredPath,
            runtime: runtime);
        Assert.DoesNotContain(discoveryResult.Effects, effect => effect is QuicConnectionPromoteActivePathEffect);

        QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            PreferredPath,
            observedAtTicks: 30);

        Assert.True(validationResult.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(PreferredPath, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.ActivePath!.Value.IsValidated);
        Assert.False(runtime.CandidatePaths.ContainsKey(PreferredPath));
        Assert.Contains(validationResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promote
            && promote.PathIdentity == PreferredPath);
    }

    private static QuicConnectionRuntime CreateRuntime()
    {
        return QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithOneRttKeysAndCommittedPeerTransportParameters(
            OriginalPath,
            CreatePeerTransportParameters());
    }

    private static QuicTransportParameters CreatePeerTransportParameters()
    {
        return new QuicTransportParameters
        {
            InitialSourceConnectionId = InitialSourceConnectionId,
            PreferredAddress = new QuicPreferredAddress
            {
                IPv4Address = PreferredIpv4Address,
                IPv4Port = 9468,
                IPv6Address = PreferredIpv6Address,
                IPv6Port = 9568,
                ConnectionId = PreferredConnectionId,
                StatelessResetToken = PreferredStatelessResetToken,
            },
        };
    }
}
