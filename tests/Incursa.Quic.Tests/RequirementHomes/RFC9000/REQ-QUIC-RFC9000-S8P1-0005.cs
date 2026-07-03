// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S8-1-P6-S3-R01")]
public sealed class REQ_QUIC_RFC9000_S8P1_0005
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="RFC9000-S8-1-P6-S3-R01">To prevent this deadlock, clients MUST send a packet on a Probe Timeout (PTO); see Section 6.2 of [QUIC-RECOVERY].</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("RFC9000-S8-1-P6-S3-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientSendsAckElicitingHandshakeAckProbeWhenServerCryptoTrafficNeedsAck()
    {
        QuicCoalescedPacketRuntimeTestSupport.CoalescedServerFlightScenario scenario =
            QuicCoalescedPacketRuntimeTestSupport.CreateClientRuntimeWithCoalescedServerFlight();

        QuicConnectionTransitionResult initialResult = scenario.ClientRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 10,
                PathIdentity: scenario.PathIdentity,
                Datagram: scenario.InitialPacket),
            nowTicks: 10);
        Assert.True(initialResult.StateChanged);

        byte[] serverHandshakeCryptoGap = CreateServerHandshakeCryptoGapPacket(scenario);
        QuicConnectionTransitionResult handshakeResult = scenario.ClientRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 11,
                PathIdentity: scenario.PathIdentity,
                Datagram: serverHandshakeCryptoGap),
            nowTicks: 11);

        QuicConnectionSendDatagramEffect probeEffect = Assert.Single(
            handshakeResult.Effects.OfType<QuicConnectionSendDatagramEffect>(),
            effect => QuicPacketParser.TryGetPacketNumberSpace(
                    effect.Datagram.Span,
                    out QuicPacketNumberSpace packetNumberSpace)
                && packetNumberSpace == QuicPacketNumberSpace.Handshake);

        Assert.Contains(
            scenario.ClientRuntime.SendRuntime.SentPackets.Values,
            sentPacket => sentPacket.PacketNumberSpace == QuicPacketNumberSpace.Handshake
                && sentPacket.AckEliciting
                && !sentPacket.AckOnlyPacket
                && !sentPacket.Retransmittable
                && sentPacket.PacketBytes.Span.SequenceEqual(probeEffect.Datagram.Span));
        Assert.NotNull(scenario.ClientRuntime.TimerState.GetDueTicks(QuicConnectionTimerKind.Recovery));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="RFC9000-S8-1-P6-S3-R01">To prevent this deadlock, clients MUST send a packet on a Probe Timeout (PTO); see Section 6.2 of [QUIC-RECOVERY].</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("RFC9000-S8-1-P6-S3-R01")]
    [Requirement("REQ-QUIC-RFC9000-S8P1-0007")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RecoveryTimerExpired_ReplaysTheBootstrapInitialWhenNoNewClientCryptoIsAvailable()
    {
        using QuicConnectionRuntime runtime = QuicS17P2P5P2TestSupport.CreateBootstrappedClientRuntime();

        long? recoveryDueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.Recovery);
        Assert.NotNull(recoveryDueTicks);
        ulong recoveryGeneration = runtime.TimerState.GetGeneration(QuicConnectionTimerKind.Recovery);

        QuicConnectionTransitionResult timerResult = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                ObservedAtTicks: recoveryDueTicks.Value,
                QuicConnectionTimerKind.Recovery,
                recoveryGeneration),
            nowTicks: recoveryDueTicks.Value);

        QuicConnectionSendDatagramEffect sendEffect = FindInitialProbeEffect(
            timerResult.Effects.OfType<QuicConnectionSendDatagramEffect>());

        Assert.True(QuicPacketParser.TryParseLongHeader(sendEffect.Datagram.Span, out QuicLongHeaderPacket packet));
        Assert.Equal(QuicLongPacketTypeBits.Initial, packet.LongPacketTypeBits);
        Assert.Contains(
            runtime.SendRuntime.SentPackets.Values,
            sentPacket => sentPacket.PacketNumberSpace == QuicPacketNumberSpace.Initial
                && sentPacket.ProbePacket
                && sentPacket.PacketBytes.Span.SequenceEqual(sendEffect.Datagram.Span));
        Assert.Contains(timerResult.Effects, effect =>
            effect is QuicConnectionArmTimerEffect armEffect
            && armEffect.TimerKind == QuicConnectionTimerKind.Recovery);
        Assert.True(runtime.TimerState.GetGeneration(QuicConnectionTimerKind.Recovery) > recoveryGeneration);
    }

    private static QuicConnectionSendDatagramEffect FindInitialProbeEffect(
        IEnumerable<QuicConnectionSendDatagramEffect> sendEffects)
    {
        foreach (QuicConnectionSendDatagramEffect sendEffect in sendEffects)
        {
            if (QuicPacketParser.TryParseLongHeader(sendEffect.Datagram.Span, out QuicLongHeaderPacket packet)
                && packet.LongPacketTypeBits == QuicLongPacketTypeBits.Initial)
            {
                return sendEffect;
            }
        }

        Assert.Fail("No Initial probe datagram was emitted when PTO expired.");
        return default!;
    }

    private static byte[] CreateServerHandshakeCryptoGapPacket(
        QuicCoalescedPacketRuntimeTestSupport.CoalescedServerFlightScenario scenario)
    {
        Assert.True(scenario.ServerRuntime.TlsState.HandshakeProtectPacketProtectionMaterial.HasValue);

        QuicHandshakeFlowCoordinator coordinator = new(
            scenario.ClientSourceConnectionId,
            scenario.ServerSourceConnectionId);

        byte[] protectedPacket = [];
        for (int i = 0; i < 3; i++)
        {
            Assert.True(coordinator.TryBuildProtectedHandshakePacket(
                [0xC0, 0xFF, 0xEE],
                cryptoPayloadOffset: 64_000,
                scenario.ServerRuntime.TlsState.HandshakeProtectPacketProtectionMaterial.Value,
                out _,
                out protectedPacket));
        }

        return protectedPacket;
    }
}
