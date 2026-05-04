using System.Net;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P6P2-0009")]
public sealed class REQ_QUIC_RFC9000_S9P6P2_0009
{
    private static readonly QuicConnectionPathIdentity OriginalPath = new("203.0.113.69", RemotePort: 443);
    private static readonly byte[] PacketNumber = [0x00, 0x00, 0x00, 0x07];
    private static readonly byte[] InitialSourceConnectionId = [0x10, 0x11, 0x12, 0x13];
    private static readonly byte[] PreferredConnectionId = [0x20, 0x21, 0x22, 0x23];
    private static readonly byte[] PreferredIpv4Address = [198, 51, 100, 69];
    private static readonly byte[] PreferredIpv6Address =
    [
        0x20, 0x01, 0x0D, 0xB8,
        0x00, 0x01, 0x00, 0x02,
        0x00, 0x03, 0x00, 0x04,
        0x00, 0x05, 0x00, 0x45,
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
        RemotePort: 9469);

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S9P6P2-0009")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PreferredAddressPathChallengeReceivesMatchingPathResponseOnThatPath()
    {
        using QuicConnectionRuntime runtime = CreateRuntime();
        byte[] challengeData = QuicS8P2PathValidationTestSupport.CreateChallengeData(0x42);
        byte[] protectedPacket = BuildProtectedPathChallengePacket(runtime, challengeData);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                PreferredPath,
                protectedPacket),
            nowTicks: 20);

        Assert.True(result.StateChanged);
        QuicS8P2PathValidationTestSupport.AssertSinglePathResponseDatagram(
            result,
            PreferredPath,
            challengeData,
            expectMinimumSize: false);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(OriginalPath, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.CandidatePaths.TryGetValue(PreferredPath, out QuicConnectionCandidatePathRecord candidatePath));
        Assert.False(candidatePath.Validation.IsValidated);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionPromoteActivePathEffect);
    }

    private static QuicConnectionRuntime CreateRuntime()
    {
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(OriginalPath);
        QuicPathMigrationRecoveryTestSupport.CommitPeerTransportParametersAndSeedOneRttPacketProtectionMaterial(
            runtime,
            CreatePeerTransportParameters());
        return runtime;
    }

    private static byte[] BuildProtectedPathChallengePacket(
        QuicConnectionRuntime runtime,
        ReadOnlySpan<byte> challengeData)
    {
        byte[] applicationPayload = QuicFrameTestData.BuildPathChallengeFrame(new QuicPathChallengeFrame(challengeData));

        Assert.True(runtime.TlsState.OneRttOpenPacketProtectionMaterial.HasValue);
        return QuicS17P3P1TestSupport.CreateProtectedApplicationDataPacket(
            runtime.CurrentPeerDestinationConnectionId.Span,
            PacketNumber,
            applicationPayload,
            runtime.TlsState.OneRttOpenPacketProtectionMaterial.Value,
            declaredPacketNumberLength: PacketNumber.Length);
    }

    private static QuicTransportParameters CreatePeerTransportParameters()
    {
        return new QuicTransportParameters
        {
            InitialSourceConnectionId = InitialSourceConnectionId,
            PreferredAddress = new QuicPreferredAddress
            {
                IPv4Address = PreferredIpv4Address,
                IPv4Port = 9469,
                IPv6Address = PreferredIpv6Address,
                IPv6Port = 9569,
                ConnectionId = PreferredConnectionId,
                StatelessResetToken = PreferredStatelessResetToken,
            },
        };
    }
}
