namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S8P1-0005")]
public sealed class REQ_QUIC_RFC9000_S8P1_0005
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S8P1-0005">To prevent this deadlock, clients MUST send a packet on a Probe Timeout (PTO); see Section 6.2 of [QUIC-RECOVERY].</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S8P1-0005")]
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
}
