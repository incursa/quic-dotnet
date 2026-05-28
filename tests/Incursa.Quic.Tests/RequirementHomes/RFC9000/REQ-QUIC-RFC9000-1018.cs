// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-1018">Endpoints MUST treat receipt of Handshake packets with other frames as a connection error of type PROTOCOL_VIOLATION.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-1018")]
public sealed class REQ_QUIC_RFC9000_1018
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryHandleHandshakePacketReceived_ClosesTheConnectionWithProtocolViolationWhenItReceivesAResetStreamFrame()
    {
        QuicCoalescedPacketRuntimeTestSupport.CoalescedServerFlightScenario scenario =
            QuicCoalescedPacketRuntimeTestSupport.CreateClientRuntimeWithCoalescedServerFlight();
        using QuicConnectionRuntime _clientRuntime = scenario.ClientRuntime;
        using QuicConnectionRuntime runtime = scenario.ServerRuntime;

        QuicConnectionTransitionResult result = ReceiveHandshakePacket(
            runtime,
            QuicFrameTestData.BuildResetStreamFrame(new QuicResetStreamFrame(0, 1, 0)),
            observedAtTicks: 21);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.NotNull(runtime.TerminalState);
        Assert.Equal(QuicConnectionCloseOrigin.Local, runtime.TerminalState!.Value.Origin);
        Assert.Equal(QuicTransportErrorCode.ProtocolViolation, runtime.TerminalState.Value.Close.TransportErrorCode);
        Assert.Null(runtime.TerminalState.Value.Close.TriggeringFrameType);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryHandleHandshakePacketReceived_AllowsTransportConnectionCloseInAHandshakePacket()
    {
        QuicCoalescedPacketRuntimeTestSupport.CoalescedServerFlightScenario scenario =
            QuicCoalescedPacketRuntimeTestSupport.CreateClientRuntimeWithCoalescedServerFlight();
        using QuicConnectionRuntime _clientRuntime = scenario.ClientRuntime;
        using QuicConnectionRuntime runtime = scenario.ServerRuntime;

        QuicConnectionTransitionResult result = ReceiveHandshakePacket(
            runtime,
            QuicFrameTestData.BuildConnectionCloseFrame(new QuicConnectionCloseFrame(
                QuicTransportErrorCode.NoError,
                triggeringFrameType: 0x04,
                [])),
            observedAtTicks: 22);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Draining, runtime.Phase);
        Assert.NotNull(runtime.TerminalState);
        Assert.Equal(QuicConnectionCloseOrigin.Remote, runtime.TerminalState!.Value.Origin);
        Assert.Equal(QuicTransportErrorCode.NoError, runtime.TerminalState.Value.Close.TransportErrorCode);
        Assert.Equal(0x04UL, runtime.TerminalState.Value.Close.TriggeringFrameType);
    }

    private static QuicConnectionTransitionResult ReceiveHandshakePacket(
        QuicConnectionRuntime runtime,
        ReadOnlySpan<byte> prefixFramePayload,
        long observedAtTicks)
    {
        Assert.True(runtime.ActivePath.HasValue);
        Assert.True(runtime.TlsState.TryGetHandshakeOpenPacketProtectionMaterial(out QuicTlsPacketProtectionMaterial handshakeMaterial));

        QuicHandshakeFlowCoordinator coordinator = new(
            runtime.CurrentPeerDestinationConnectionId,
            runtime.CurrentHandshakeSourceConnectionId);
        Assert.True(coordinator.TryBuildProtectedHandshakePacket(
            QuicS12P3TestSupport.CreateSequentialBytes(0x40, 20),
            cryptoPayloadOffset: 0,
            prefixFramePayload,
            handshakeMaterial,
            out byte[] protectedPacket));

        return runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: observedAtTicks,
                runtime.ActivePath!.Value.Identity,
                protectedPacket),
            nowTicks: observedAtTicks);
    }
}
