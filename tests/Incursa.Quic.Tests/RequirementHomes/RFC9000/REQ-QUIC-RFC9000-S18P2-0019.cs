using System.Net;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S18P2-0019")]
public sealed class REQ_QUIC_RFC9000_S18P2_0019
{
    private static readonly QuicConnectionPathIdentity OriginalPath = new("203.0.113.70", RemotePort: 443);
    private static readonly byte[] InitialDestinationConnectionId = [0x10, 0x11, 0x12, 0x13];
    private static readonly byte[] InitialSourceConnectionId = [0x14, 0x15, 0x16, 0x17];
    private static readonly byte[] PreferredConnectionId = [0x20, 0x21, 0x22, 0x23];
    private static readonly byte[] PreferredIpv4Address = [198, 51, 100, 70];
    private static readonly byte[] PreferredIpv6Address = [0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x46];
    private static readonly byte[] PreferredStatelessResetToken = [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F];
    private static readonly QuicConnectionPathIdentity PreferredPath = new(new IPAddress(PreferredIpv4Address).ToString(), RemotePort: 9443);

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientUsesPreferredAddressTransportParameterToChangeServerAddressAfterValidationCompletes()
    {
        using QuicConnectionRuntime runtime = CreateRuntime();

        QuicConnectionTransitionResult receiveResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                PreferredPath,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 20);

        Assert.True(receiveResult.StateChanged);
        Assert.True(runtime.CandidatePaths.TryGetValue(PreferredPath, out QuicConnectionCandidatePathRecord candidatePath));
        Assert.False(candidatePath.Validation.IsValidated);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(OriginalPath, runtime.ActivePath!.Value.Identity);

        QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            PreferredPath,
            observedAtTicks: 30);

        Assert.True(validationResult.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(PreferredPath, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.ActivePath!.Value.IsValidated);
        Assert.Equal(PreferredPath.RemoteAddress, runtime.LastValidatedRemoteAddress);
        Assert.True(runtime.CurrentPeerDestinationConnectionId.Span.SequenceEqual(PreferredConnectionId));
        Assert.Contains(validationResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promoteActivePathEffect
            && promoteActivePathEffect.PathIdentity == PreferredPath
            && !promoteActivePathEffect.RestoreSavedState);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClientKeepsOriginalServerAddressBeforePreferredAddressValidationCompletes()
    {
        using QuicConnectionRuntime runtime = CreateRuntime();

        QuicConnectionTransitionResult receiveResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                PreferredPath,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 20);

        Assert.True(receiveResult.StateChanged);
        Assert.True(runtime.CandidatePaths.TryGetValue(PreferredPath, out QuicConnectionCandidatePathRecord candidatePath));
        Assert.False(candidatePath.Validation.IsValidated);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(OriginalPath, runtime.ActivePath!.Value.Identity);
        Assert.False(runtime.CurrentPeerDestinationConnectionId.Span.SequenceEqual(PreferredConnectionId));
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

    private static QuicTransportParameters CreatePeerTransportParameters()
    {
        return new QuicTransportParameters
        {
            InitialSourceConnectionId = InitialSourceConnectionId,
            PreferredAddress = new QuicPreferredAddress
            {
                IPv4Address = PreferredIpv4Address,
                IPv4Port = 9443,
                IPv6Address = PreferredIpv6Address,
                IPv6Port = 9553,
                ConnectionId = PreferredConnectionId,
                StatelessResetToken = PreferredStatelessResetToken,
            },
        };
    }
}
