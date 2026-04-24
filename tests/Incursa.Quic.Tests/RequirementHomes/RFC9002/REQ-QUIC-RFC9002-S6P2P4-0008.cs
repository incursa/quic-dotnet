using System.Reflection;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P2P4-0008">When there is no data to send, the sender SHOULD send a PING or other ack-eliciting frame in a single packet, rearming the PTO timer.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S6P2P4-0008")]
public sealed class REQ_QUIC_RFC9002_S6P2P4_0008
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatPingFrame_ProvidesTheFallbackProbeWhenNoDataIsAvailable()
    {
        Span<byte> destination = stackalloc byte[1];

        Assert.True(QuicFrameCodec.TryFormatPingFrame(destination, out int bytesWritten));
        Assert.Equal(1, bytesWritten);
        Assert.True(QuicFrameCodec.IsAckElicitingFrameType(0x01));

        Assert.True(QuicFrameCodec.TryParsePingFrame(destination, out int bytesConsumed));
        Assert.Equal(1, bytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RecoveryPto_FallsBackToAPingProbeWhenNoRetransmittableDataExists()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateConfirmedClientRuntimeWithValidatedActivePath();

        Assert.True(runtime.ActivePath.HasValue);
        Assert.Empty(runtime.SendRuntime.SentPackets);

        TrackNonRetransmittableApplicationAckElicitingPacket(runtime);
        QuicConnectionEffect[] timerEffects = InvokeRecomputeLifecycleTimerEffects(runtime);

        long? recoveryDueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.Recovery);
        Assert.NotNull(recoveryDueTicks);
        Assert.Contains(timerEffects, effect => effect is QuicConnectionArmTimerEffect arm && arm.TimerKind == QuicConnectionTimerKind.Recovery);
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
        QuicConnectionSendDatagramEffect sendEffect = Assert.Single(sendEffects);

        QuicHandshakeFlowCoordinator coordinator = new(runtime.CurrentPeerDestinationConnectionId);
        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            sendEffect.Datagram.Span,
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength,
            out bool keyPhase));

        Assert.False(keyPhase);

        ReadOnlySpan<byte> packetPayload = openedPacket.AsSpan(payloadOffset, payloadLength);
        Assert.True(QuicFrameCodec.TryParsePingFrame(packetPayload, out int pingBytesConsumed));
        Assert.Equal(1, pingBytesConsumed);
        QuicConnectionSentPacket sentProbePacket = Assert.Single(
            runtime.SendRuntime.SentPackets.Values,
            packet => packet.PacketBytes.Span.SequenceEqual(sendEffect.Datagram.Span));
        Assert.True(sentProbePacket.ProbePacket);
        Assert.False(sentProbePacket.Retransmittable);

        for (int index = pingBytesConsumed; index < packetPayload.Length; index++)
        {
            Assert.Equal(0x00, packetPayload[index]);
        }

        Assert.NotNull(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.Recovery));
        Assert.True(runtime.TimerState.GetGeneration(QuicConnectionTimerKind.Recovery) > recoveryGeneration);
        Assert.Contains(timerResult.Effects, effect => effect is QuicConnectionArmTimerEffect arm && arm.TimerKind == QuicConnectionTimerKind.Recovery);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryFormatPingFrame_RejectsInsufficientSpaceForTheFallbackProbe()
    {
        Assert.False(QuicFrameCodec.TryFormatPingFrame(stackalloc byte[0], out _));
    }

    private static void TrackNonRetransmittableApplicationAckElicitingPacket(QuicConnectionRuntime runtime)
    {
        Span<byte> pingPayload = stackalloc byte[1];
        Assert.True(QuicFrameCodec.TryFormatPingFrame(pingPayload, out int bytesWritten));

        QuicHandshakeFlowCoordinator coordinator = new(runtime.CurrentPeerDestinationConnectionId);
        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            pingPayload[..bytesWritten],
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            runtime.TlsState.CurrentOneRttKeyPhaseBit,
            out ulong packetNumber,
            out byte[] protectedPacket));

        MethodInfo method = typeof(QuicConnectionRuntime).GetMethod(
            "TrackApplicationPacket",
            BindingFlags.Instance | BindingFlags.NonPublic)!;

        method.Invoke(
            runtime,
            [
                packetNumber,
                protectedPacket,
                true,
                false,
                false,
                false,
                QuicTlsEncryptionLevel.OneRtt,
                null,
                default(ReadOnlyMemory<byte>),
            ]);
    }

    private static QuicConnectionEffect[] InvokeRecomputeLifecycleTimerEffects(QuicConnectionRuntime runtime)
    {
        MethodInfo method = typeof(QuicConnectionRuntime).GetMethod(
            "RecomputeLifecycleTimerEffects",
            BindingFlags.Instance | BindingFlags.NonPublic)!;

        return (QuicConnectionEffect[])method.Invoke(runtime, [])!;
    }
}
