namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-SAP9-0004">When PTO fires, the sender MUST send one or two ack-eliciting packets in the selected packet number space.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-SAP9-0004")]
public sealed class REQ_QUIC_RFC9002_SAP9_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CanSend_AllowsAnAckElicitingProbePacketWhenTheCongestionWindowIsFull()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(state.CongestionWindowBytes);

        Span<byte> probeFrame = stackalloc byte[1];
        Assert.True(QuicFrameCodec.TryFormatPingFrame(probeFrame, out int bytesWritten));
        Assert.Equal(1, bytesWritten);
        Assert.True(QuicFrameCodec.IsAckElicitingFrameType(probeFrame[0]));

        Assert.True(state.CanSend(1, isProbePacket: true));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void CanSend_RejectsNonProbePacketsWhenTheCongestionWindowIsFull()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(state.CongestionWindowBytes);

        Assert.False(state.CanSend(1, isProbePacket: false));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void CanSend_AllowsTwoFullSizedProbeDatagramsWhenTheCongestionWindowIsFull()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(state.CongestionWindowBytes);
        ulong fullSizedDatagramBytes = state.MaxDatagramSizeBytes;

        Assert.True(state.CanSend(fullSizedDatagramBytes, isProbePacket: true));
        state.RegisterPacketSent(fullSizedDatagramBytes, isProbePacket: true);

        Assert.True(state.CanSend(fullSizedDatagramBytes, isProbePacket: true));
        state.RegisterPacketSent(fullSizedDatagramBytes, isProbePacket: true);

        Assert.Equal(
            state.CongestionWindowBytes + (2 * fullSizedDatagramBytes),
            state.BytesInFlightBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RecoveryTimerExpired_UsesBothProbeDatagramsInTheSelectedInitialSpaceWhenNoOtherSpaceHasEligibleData()
    {
        // Provenance:
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260421-174847444-client-chrome\
        //   runner-logs\quic-go_chrome\handshakeloss\output.txt
        //   runner-logs\quic-go_chrome\handshakeloss\client\qlog\client-multiconnect-30038d17ec554951a7c68a2909543799.qlog
        // Connection 11/50 timed out during the handshake after the server's coalesced response was lost.
        // The failing trace showed repeated client Initial retransmissions without a follow-up Handshake
        // packet, so the selected PTO space remained Initial. When no other packet-number space has
        // eligible probe data, RFC 9002 still allows the sender to spend its second probe datagram in
        // the selected Initial space to avoid consecutive PTO expiry on a single lost datagram.
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

        QuicConnectionSendDatagramEffect[] sendEffects = timerResult.Effects
            .OfType<QuicConnectionSendDatagramEffect>()
            .ToArray();
        Assert.Equal(2, sendEffects.Length);
        Assert.All(sendEffects, sendEffect =>
        {
            Assert.True(QuicPacketParser.TryParseLongHeader(sendEffect.Datagram.Span, out QuicLongHeaderPacket packet));
            Assert.Equal(QuicLongPacketTypeBits.Initial, packet.LongPacketTypeBits);
        });
        Assert.False(sendEffects[0].Datagram.Span.SequenceEqual(sendEffects[1].Datagram.Span));
        Assert.Equal(
            2,
            runtime.SendRuntime.SentPackets.Values.Count(sentPacket =>
                sentPacket.PacketNumberSpace == QuicPacketNumberSpace.Initial
                && sentPacket.ProbePacket));
        Assert.Contains(timerResult.Effects, effect =>
            effect is QuicConnectionArmTimerEffect armEffect
            && armEffect.TimerKind == QuicConnectionTimerKind.Recovery
            && armEffect.Generation > recoveryGeneration);
    }
}
