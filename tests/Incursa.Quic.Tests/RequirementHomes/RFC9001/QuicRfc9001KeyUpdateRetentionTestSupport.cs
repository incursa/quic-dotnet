using System.Diagnostics;
using System.Reflection;

namespace Incursa.Quic.Tests;

internal static class QuicRfc9001KeyUpdateRetentionTestSupport
{
    internal static void ConfigureRuntime(QuicConnectionRuntime runtime)
    {
        QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);
        MarkServerHandshakeDoneAsAlreadySent(runtime);
    }

    internal static QuicConnectionTransitionResult ReceiveCurrentPhaseOnePacket(
        QuicConnectionRuntime runtime,
        long observedAtTicks)
    {
        QuicTlsPacketProtectionMaterial currentOpenMaterial =
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value;
        QuicHandshakeFlowCoordinator peerCoordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();
        Assert.True(peerCoordinator.TryBuildProtectedApplicationDataPacket(
            QuicRfc9001KeyPhaseTestSupport.CreatePingPayload(),
            currentOpenMaterial,
            keyPhase: true,
            out _,
            out byte[] protectedPacket));

        return runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: observedAtTicks,
                QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                protectedPacket),
            nowTicks: observedAtTicks);
    }

    internal static void SeedTrackedOneRttPacket(
        QuicConnectionRuntime runtime,
        ulong packetNumber,
        ulong sentAtMicros,
        uint keyPhase)
    {
        runtime.SendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber,
            PayloadBytes: 1_200,
            SentAtMicros: sentAtMicros,
            AckEliciting: true,
            Retransmittable: true,
            PacketBytes: new byte[] { (byte)(packetNumber & 0xFF) },
            PacketProtectionLevel: QuicTlsEncryptionLevel.OneRtt,
            OneRttKeyPhase: keyPhase));
        GetRecoveryController(runtime).RecordPacketSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber,
            sentAtMicros,
            isAckElicitingPacket: true,
            packetProtectionLevel: QuicTlsEncryptionLevel.OneRtt,
            oneRttKeyPhase: keyPhase);
    }

    internal static void SeedLostOneRttPacket(
        QuicConnectionRuntime runtime,
        ulong packetNumber,
        ulong sentAtMicros,
        uint keyPhase)
    {
        SeedTrackedOneRttPacket(runtime, packetNumber, sentAtMicros, keyPhase);
        Assert.True(runtime.SendRuntime.TryRegisterLoss(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber,
            handshakeConfirmed: true));
    }

    internal static QuicConnectionTransitionResult ExpireKeyUpdateRetentionTimer(QuicConnectionRuntime runtime)
    {
        long dueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.KeyUpdateRetention)!.Value;
        ulong generation = runtime.TimerState.GetGeneration(QuicConnectionTimerKind.KeyUpdateRetention);

        return runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                ObservedAtTicks: dueTicks,
                QuicConnectionTimerKind.KeyUpdateRetention,
                generation),
            nowTicks: dueTicks);
    }

    internal static QuicRecoveryController GetRecoveryController(QuicConnectionRuntime runtime)
    {
        FieldInfo recoveryControllerField = typeof(QuicConnectionRuntime).GetField(
            "recoveryController",
            BindingFlags.NonPublic | BindingFlags.Instance)!;
        return (QuicRecoveryController)recoveryControllerField.GetValue(runtime)!;
    }

    internal static ulong ConvertTicksToMicros(long ticks)
    {
        if (ticks <= 0)
        {
            return 0;
        }

        ulong numerator = (ulong)ticks;
        return (numerator * 1_000_000UL) / (ulong)Stopwatch.Frequency;
    }

    private static void MarkServerHandshakeDoneAsAlreadySent(QuicConnectionRuntime runtime)
    {
        if (runtime.TlsState.Role != QuicTlsRole.Server)
        {
            return;
        }

        FieldInfo handshakeDonePacketSentField = typeof(QuicConnectionRuntime).GetField(
            "handshakeDonePacketSent",
            BindingFlags.NonPublic | BindingFlags.Instance)!;
        handshakeDonePacketSentField.SetValue(runtime, true);
    }
}
