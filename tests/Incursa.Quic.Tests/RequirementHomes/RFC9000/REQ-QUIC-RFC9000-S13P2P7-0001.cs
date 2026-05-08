using System.Reflection;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S13P2P7-0001")]
public sealed class REQ_QUIC_RFC9000_S13P2P7_0001
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P2P7-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RecoveryTimerExpired_SendsPeriodicPingProbeWhenNoRetransmittablePayloadIsAvailable()
    {
        QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport.CreateConfirmedClientRuntimeWithValidatedActivePath();
        List<QuicConnectionEffect>? effects = [];

        Assert.True(InvokeTrySendRecoveryPingProbe(runtime, ref effects));
        Assert.NotNull(effects);
        QuicConnectionSendDatagramEffect firstSend =
            Assert.Single(effects.OfType<QuicConnectionSendDatagramEffect>());
        AssertProtectedApplicationPayloadIsPingOnly(runtime, firstSend);

        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> firstTrackedPacket =
            QuicS13AckPiggybackTestSupport.FindTrackedPacket(runtime, firstSend.Datagram);
        Assert.True(firstTrackedPacket.Value.AckEliciting);
        Assert.False(firstTrackedPacket.Value.AckOnlyPacket);
        Assert.True(firstTrackedPacket.Value.ProbePacket);
        Assert.False(firstTrackedPacket.Value.Retransmittable);

        _ = InvokeRecomputeLifecycleTimerEffects(runtime);
        long? recoveryDueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.Recovery);
        Assert.NotNull(recoveryDueTicks);
        ulong recoveryGeneration = runtime.TimerState.GetGeneration(QuicConnectionTimerKind.Recovery);

        QuicConnectionTransitionResult timerResult = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                recoveryDueTicks.Value,
                QuicConnectionTimerKind.Recovery,
                recoveryGeneration),
            nowTicks: recoveryDueTicks.Value);

        QuicConnectionSendDatagramEffect secondSend =
            Assert.Single(timerResult.Effects.OfType<QuicConnectionSendDatagramEffect>());
        AssertProtectedApplicationPayloadIsPingOnly(runtime, secondSend);

        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> secondTrackedPacket =
            QuicS13AckPiggybackTestSupport.FindTrackedPacket(runtime, secondSend.Datagram);
        Assert.True(secondTrackedPacket.Value.AckEliciting);
        Assert.False(secondTrackedPacket.Value.AckOnlyPacket);
        Assert.True(secondTrackedPacket.Value.ProbePacket);
        Assert.False(secondTrackedPacket.Value.Retransmittable);
        Assert.True(secondTrackedPacket.Key.PacketNumber > firstTrackedPacket.Key.PacketNumber);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P2P7-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RecoveryPingProbe_DoesNotSendPaddingOnlyProbeWithoutActivePathOrOneRttKeys()
    {
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntime();
        List<QuicConnectionEffect>? effects = [];

        Assert.False(InvokeTrySendRecoveryPingProbe(runtime, ref effects));
        Assert.NotNull(effects);
        Assert.Empty(effects);
    }

    private static bool InvokeTrySendRecoveryPingProbe(
        QuicConnectionRuntime runtime,
        ref List<QuicConnectionEffect>? effects)
    {
        MethodInfo method = typeof(QuicConnectionRuntime).GetMethod(
            "TrySendRecoveryPingProbe",
            BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new MissingMethodException(
                nameof(QuicConnectionRuntime),
                "TrySendRecoveryPingProbe");

        object?[] arguments = [effects];
        bool result = (bool)method.Invoke(runtime, arguments)!;
        effects = (List<QuicConnectionEffect>?)arguments[0];
        return result;
    }

    private static QuicConnectionEffect[] InvokeRecomputeLifecycleTimerEffects(QuicConnectionRuntime runtime)
    {
        MethodInfo method = typeof(QuicConnectionRuntime).GetMethod(
            "RecomputeLifecycleTimerEffects",
            BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new MissingMethodException(
                nameof(QuicConnectionRuntime),
                "RecomputeLifecycleTimerEffects");

        return (QuicConnectionEffect[])method.Invoke(runtime, [])!;
    }

    private static void AssertProtectedApplicationPayloadIsPingOnly(
        QuicConnectionRuntime runtime,
        QuicConnectionSendDatagramEffect sendEffect)
    {
        byte[] payload = QuicS13AckPiggybackTestSupport.OpenOutgoingApplicationPayload(runtime, sendEffect);

        ReadOnlySpan<byte> remaining = QuicS13AckPiggybackTestSupport.SkipPadding(payload);
        Assert.False(remaining.IsEmpty);
        Assert.True(QuicFrameCodec.TryParsePingFrame(remaining, out int pingBytesConsumed));
        Assert.Equal(1, pingBytesConsumed);

        ReadOnlySpan<byte> tail = QuicS13AckPiggybackTestSupport.SkipPadding(remaining[pingBytesConsumed..]);
        Assert.True(tail.IsEmpty);
    }
}
