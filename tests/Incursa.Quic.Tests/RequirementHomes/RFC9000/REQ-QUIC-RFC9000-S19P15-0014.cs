namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P15-0014")]
public sealed class REQ_QUIC_RFC9000_S19P15_0014
{
    private static readonly byte[] LocalSourceConnectionId =
    [
        0x41, 0x42, 0x43, 0x44,
    ];

    private static readonly byte[] PeerDestinationConnectionId =
    [
        0x51, 0x52, 0x53,
    ];

    private static readonly byte[] IssuedConnectionId =
    [
        0x61, 0x62, 0x63, 0x64,
    ];

    private static readonly QuicConnectionPathIdentity ActivePath =
        new("203.0.113.210", RemotePort: 443);

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0014")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void ConnectionIdIssuedEvent_WhenLocalZeroLengthModeIsCommitted_DoesNotSendNewConnectionId()
    {
        using QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntime();

        CommitLocalTransportParameters(runtime, []);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionConnectionIdIssuedEvent(
                ObservedAtTicks: 1,
                ConnectionId: 1UL,
                StatelessResetToken: QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0x70),
                ConnectionIdBytes: IssuedConnectionId),
            nowTicks: 1);

        Assert.False(result.StateChanged);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionRegisterConnectionIdRouteEffect);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionRegisterStatelessResetTokenEffect);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionSendDatagramEffect);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0014")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void ConnectionIdIssuedEvent_WhenLocalNonZeroModeIsCommitted_CanSendNewConnectionId()
    {
        using QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntime();

        CommitLocalTransportParameters(runtime, LocalSourceConnectionId);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionConnectionIdIssuedEvent(
                ObservedAtTicks: 1,
                ConnectionId: 1UL,
                StatelessResetToken: QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0x80),
                ConnectionIdBytes: IssuedConnectionId),
            nowTicks: 1);

        Assert.True(result.StateChanged);
        Assert.Contains(
            result.Effects,
            effect => effect is QuicConnectionRegisterConnectionIdRouteEffect route
                && route.ConnectionId == 1UL
                && route.ConnectionIdBytes.Span.SequenceEqual(IssuedConnectionId));
        Assert.Contains(
            result.Effects,
            effect => effect is QuicConnectionRegisterStatelessResetTokenEffect token
                && token.ConnectionId == 1UL);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0014")]
    [CoverageType(RequirementCoverageType.Edge)]
    public void PreviouslyUnusedIssuedConnectionId_WhenLocalZeroLengthModeIsCommitted_DoesNotReplenish()
    {
        using QuicConnectionRuntime runtime = CreateActiveRuntimeWithOneRttProtection();

        QuicConnectionTransitionResult issued = runtime.Transition(
            new QuicConnectionConnectionIdIssuedEvent(
                ObservedAtTicks: 3,
                ConnectionId: 1UL,
                StatelessResetToken: QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0x90),
                ConnectionIdBytes: IssuedConnectionId),
            nowTicks: 3);

        Assert.True(issued.StateChanged);
        CommitLocalTransportParameters(runtime, []);

        byte[] datagram = BuildOneRttPacket(
            runtime,
            IssuedConnectionId,
            QuicFrameTestData.BuildPingFrame());

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 4,
                ActivePath,
                datagram,
                RoutedLocallyIssuedConnectionId: 1UL),
            nowTicks: 4);

        Assert.True(result.StateChanged);
        Assert.DoesNotContain(
            result.Effects,
            effect => effect is QuicConnectionRegisterConnectionIdRouteEffect route
                && route.ConnectionId == 2UL);
        Assert.DoesNotContain(
            result.Effects,
            effect => effect is QuicConnectionRegisterStatelessResetTokenEffect token
                && token.ConnectionId == 2UL);
    }

    private static QuicConnectionRuntime CreateActiveRuntimeWithOneRttProtection()
    {
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(ActivePath);
        Assert.True(runtime.TrySetHandshakeDestinationConnectionId(PeerDestinationConnectionId));
        Assert.True(runtime.TrySetHandshakeSourceConnectionId(LocalSourceConnectionId));

        QuicTransportParameters peerTransportParameters = QuicPostHandshakeTicketTestSupport.CreatePeerTransportParameters();
        peerTransportParameters.InitialSourceConnectionId = PeerDestinationConnectionId.ToArray();
        peerTransportParameters.ActiveConnectionIdLimit = 3UL;
        QuicPathMigrationRecoveryTestSupport.CommitPeerTransportParametersAndSeedOneRttPacketProtectionMaterial(
            runtime,
            peerTransportParameters);

        return runtime;
    }

    private static void CommitLocalTransportParameters(
        QuicConnectionRuntime runtime,
        ReadOnlySpan<byte> initialSourceConnectionId)
    {
        QuicTransportParameters localTransportParameters = new()
        {
            MaxIdleTimeout = 15,
            InitialSourceConnectionId = initialSourceConnectionId.ToArray(),
        };

        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 0,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.LocalTransportParametersReady,
                    TransportParameters: localTransportParameters)),
            nowTicks: 0).StateChanged);
        Assert.NotNull(runtime.TlsState.LocalTransportParameters);
        Assert.Equal(
            initialSourceConnectionId.ToArray(),
            runtime.TlsState.LocalTransportParameters!.InitialSourceConnectionId);
    }

    private static byte[] BuildOneRttPacket(
        QuicConnectionRuntime runtime,
        ReadOnlySpan<byte> destinationConnectionId,
        ReadOnlySpan<byte> payload)
    {
        Assert.True(runtime.TlsState.OneRttOpenPacketProtectionMaterial.HasValue);
        QuicHandshakeFlowCoordinator coordinator = new(
            destinationConnectionId.ToArray(),
            LocalSourceConnectionId);

        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            payload,
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value,
            runtime.TlsState.CurrentOneRttKeyPhase == 1,
            out byte[] protectedPacket));

        return protectedPacket;
    }
}
