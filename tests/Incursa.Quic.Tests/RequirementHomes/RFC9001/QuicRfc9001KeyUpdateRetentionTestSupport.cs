// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Diagnostics;
namespace Incursa.Quic.Tests;

internal static class QuicRfc9001KeyUpdateRetentionTestSupport
{
    internal const double RuntimeTestConfidentialityLimitPackets = 64d;
    internal const double RuntimeTestIntegrityLimitPackets = 128d;

    internal static void ConfigureRuntime(QuicConnectionRuntime runtime)
    {
        QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);
        MarkServerHandshakeDoneAsAlreadySent(runtime);
    }

    internal static QuicAeadKeyLifecycle ReplaceCurrentOneRttProtectKeyLifecycleForTest(
        QuicConnectionRuntime runtime)
    {
        return ReplaceOneRttAeadKeyLifecycleForTest(
            runtime,
            "currentOneRttProtectKeyLifecycle",
            RuntimeTestConfidentialityLimitPackets,
            RuntimeTestIntegrityLimitPackets);
    }

    internal static QuicAeadKeyLifecycle ReplaceCurrentOneRttOpenKeyLifecycleForTest(
        QuicConnectionRuntime runtime)
    {
        return ReplaceOneRttAeadKeyLifecycleForTest(
            runtime,
            "currentOneRttOpenKeyLifecycle",
            RuntimeTestConfidentialityLimitPackets,
            RuntimeTestIntegrityLimitPackets);
    }

    internal static QuicAeadKeyLifecycle ReplaceRetainedOldOneRttOpenKeyLifecycleForTest(
        QuicConnectionRuntime runtime)
    {
        return ReplaceOneRttAeadKeyLifecycleForTest(
            runtime,
            "retainedOldOneRttOpenKeyLifecycle",
            RuntimeTestConfidentialityLimitPackets,
            RuntimeTestIntegrityLimitPackets);
    }

    internal static QuicConnectionTransitionResult ReceiveCurrentPhaseOnePacket(
        QuicConnectionRuntime runtime,
        long observedAtTicks)
    {
        return ReceiveCurrentPhasePacket(runtime, observedAtTicks, keyPhase: true);
    }

    internal static QuicConnectionTransitionResult ReceiveCurrentPhasePacket(
        QuicConnectionRuntime runtime,
        long observedAtTicks)
    {
        return ReceiveCurrentPhasePacket(
            runtime,
            observedAtTicks,
            runtime.TlsState.CurrentOneRttKeyPhaseBit);
    }

    private static QuicConnectionTransitionResult ReceiveCurrentPhasePacket(
        QuicConnectionRuntime runtime,
        long observedAtTicks,
        bool keyPhase)
    {
        QuicTlsPacketProtectionMaterial currentOpenMaterial =
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value;
        QuicHandshakeFlowCoordinator peerCoordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();
        Assert.True(peerCoordinator.TryBuildProtectedApplicationDataPacket(
            QuicRfc9001KeyPhaseTestSupport.CreatePingPayload(),
            currentOpenMaterial,
            keyPhase,
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
        ulong keyPhase)
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
        ulong keyPhase)
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
        return runtime.RecoveryController;
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

        runtime.MarkHandshakeDonePacketSentForTests();
    }

    private static QuicAeadKeyLifecycle ReplaceOneRttAeadKeyLifecycleForTest(
        QuicConnectionRuntime runtime,
        string fieldName,
        double confidentialityLimitPackets,
        double integrityLimitPackets)
    {
        QuicAeadKeyLifecycle lifecycle = new(new QuicAeadUsageLimits(
            confidentialityLimitPackets,
            integrityLimitPackets));
        Assert.True(lifecycle.TryActivate());

        switch (fieldName)
        {
            case "currentOneRttProtectKeyLifecycle":
                runtime.TlsState.SetCurrentOneRttProtectKeyLifecycleForTests(lifecycle);
                break;
            case "currentOneRttOpenKeyLifecycle":
                runtime.TlsState.SetCurrentOneRttOpenKeyLifecycleForTests(lifecycle);
                break;
            case "retainedOldOneRttOpenKeyLifecycle":
                runtime.TlsState.SetRetainedOldOneRttOpenKeyLifecycleForTests(lifecycle);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(fieldName), fieldName, "Unknown lifecycle field name.");
        }

        return lifecycle;
    }
}
