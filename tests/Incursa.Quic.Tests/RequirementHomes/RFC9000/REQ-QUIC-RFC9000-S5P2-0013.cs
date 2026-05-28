// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S5P2-0013")]
public sealed class REQ_QUIC_RFC9000_S5P2_0013
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void InitialPacketPreValidationRevertsPotentialCryptoSideEffects()
    {
        byte[] initialDestinationConnectionId =
        [
            0x83, 0x94, 0xC8, 0xF0,
            0x3E, 0x51, 0x57, 0x08,
        ];
        using QuicConnectionRuntime runtime =
            QuicS5P2PacketAssociationTestSupport.CreateServerRuntimeWithInitialProtection(initialDestinationConnectionId);
        byte[] cryptoPayload = QuicFrameTestData.BuildCryptoFrame(
            new QuicCryptoFrame(0, [0x60, 0x61, 0x62, 0x63]));
        byte[] resetStreamPayload = QuicFrameTestData.BuildResetStreamFrame(new QuicResetStreamFrame(0, 1, 0));
        byte[] plaintextPayload = [.. cryptoPayload, .. resetStreamPayload];
        byte[] protectedPacket = QuicS5P2PacketAssociationTestSupport.BuildProtectedClientInitialPacket(
            initialDestinationConnectionId,
            plaintextPayload);

        _ = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 0,
                new QuicConnectionPathIdentity("203.0.113.70", RemotePort: 443),
                protectedPacket),
            nowTicks: 0);

        Assert.Equal(0, runtime.TlsState.InitialIngressCryptoBuffer.BufferedBytes);
        Assert.False(runtime.PeerHandshakeTranscriptCompleted);
        Assert.NotNull(runtime.TerminalState);
        Assert.Equal(QuicTransportErrorCode.ProtocolViolation, runtime.TerminalState!.Value.Close.TransportErrorCode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void HandshakePacketPreValidationRevertsPotentialCryptoSideEffects()
    {
        QuicCoalescedPacketRuntimeTestSupport.CoalescedServerFlightScenario scenario =
            QuicCoalescedPacketRuntimeTestSupport.CreateClientRuntimeWithCoalescedServerFlight();
        using QuicConnectionRuntime clientRuntime = scenario.ClientRuntime;
        using QuicConnectionRuntime serverRuntime = scenario.ServerRuntime;

        byte[] prefixThenForbiddenPayload =
        [
            .. QuicFrameTestData.BuildPingFrame(),
            .. QuicFrameTestData.BuildResetStreamFrame(new QuicResetStreamFrame(0, 1, 0)),
        ];
        byte[] protectedPacket = QuicS5P2PacketAssociationTestSupport.BuildProtectedHandshakePacket(
            serverRuntime,
            prefixThenForbiddenPayload,
            cryptoStart: 0x70);

        _ = serverRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 21,
                scenario.PathIdentity,
                protectedPacket),
            nowTicks: 21);

        Assert.Equal(0, serverRuntime.TlsState.HandshakeIngressCryptoBuffer.BufferedBytes);
        Assert.False(serverRuntime.PeerHandshakeTranscriptCompleted);
        Assert.NotNull(serverRuntime.TerminalState);
        Assert.Equal(QuicTransportErrorCode.ProtocolViolation, serverRuntime.TerminalState!.Value.Close.TransportErrorCode);
    }
}
