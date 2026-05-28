// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0238")]
public sealed class REQ_QUIC_RFC9000_0238
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
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ConnectionIdIssuedEvent_WhenLocalTransportParametersSelectZeroLengthConnectionId_DoesNotIssueNewConnectionId()
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
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ConnectionIdIssuedEvent_WhenLocalTransportParametersSelectNonZeroConnectionId_IssuesNewConnectionId()
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
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
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

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void RetireConnectionIdFrame_WhenPeerRequestedZeroLengthDestinationConnectionId_RetiresLocalPreferredAddressConnectionId()
    {
        using QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateServerRuntimeWithActivePath(ActivePath);
        Assert.True(runtime.TrySetHandshakeDestinationConnectionId(ReadOnlySpan<byte>.Empty));
        Assert.True(runtime.TrySetHandshakeSourceConnectionId(LocalSourceConnectionId));

        QuicPreferredAddress preferredAddress = QuicPreferredAddressRequirementTestSupport.CreatePreferredAddress();
        QuicConnectionTransitionResult localParametersCommitted = CommitLocalTransportParameters(
            runtime,
            LocalSourceConnectionId,
            preferredAddress);

        Assert.Contains(
            localParametersCommitted.Effects,
            effect => effect is QuicConnectionRegisterConnectionIdRouteEffect route
                && route.ConnectionId == 1UL
                && route.ConnectionIdBytes.Span.SequenceEqual(preferredAddress.ConnectionId));
        Assert.Contains(
            localParametersCommitted.Effects,
            effect => effect is QuicConnectionRegisterStatelessResetTokenEffect token
                && token.ConnectionId == 1UL
                && token.Token.Span.SequenceEqual(preferredAddress.StatelessResetToken));

        QuicTransportParameters peerTransportParameters = QuicPostHandshakeTicketTestSupport.CreatePeerTransportParameters();
        peerTransportParameters.InitialSourceConnectionId = [];
        peerTransportParameters.ActiveConnectionIdLimit = 2UL;
        QuicPathMigrationRecoveryTestSupport.CommitPeerTransportParametersAndSeedOneRttPacketProtectionMaterial(
            runtime,
            peerTransportParameters);

        byte[] retirePreferredAddressConnectionIdPayload =
            QuicFrameTestData.BuildRetireConnectionIdFrame(new QuicRetireConnectionIdFrame(1UL));

        QuicConnectionTransitionResult result = QuicS19P16RetireConnectionIdTestSupport.TransitionOneRttPacket(
            runtime,
            ActivePath,
            LocalSourceConnectionId,
            retirePreferredAddressConnectionIdPayload,
            observedAtTicks: 5);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.Contains(
            result.Effects,
            effect => effect is QuicConnectionRetireConnectionIdRouteEffect route
                && route.ConnectionId == 1UL
                && route.ConnectionIdBytes.Span.SequenceEqual(preferredAddress.ConnectionId));
        Assert.Contains(
            result.Effects,
            effect => effect is QuicConnectionRetireStatelessResetTokenEffect token
                && token.ConnectionId == 1UL);
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

    private static QuicConnectionTransitionResult CommitLocalTransportParameters(
        QuicConnectionRuntime runtime,
        ReadOnlySpan<byte> initialSourceConnectionId,
        QuicPreferredAddress? preferredAddress = null)
    {
        QuicTransportParameters localTransportParameters = new()
        {
            MaxIdleTimeout = 15,
            InitialSourceConnectionId = initialSourceConnectionId.ToArray(),
            PreferredAddress = preferredAddress,
        };

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 0,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.LocalTransportParametersReady,
                    TransportParameters: localTransportParameters)),
            nowTicks: 0);

        Assert.True(result.StateChanged);
        Assert.NotNull(runtime.TlsState.LocalTransportParameters);
        Assert.Equal(
            initialSourceConnectionId.ToArray(),
            runtime.TlsState.LocalTransportParameters!.InitialSourceConnectionId);
        return result;
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
