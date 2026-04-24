using System.Diagnostics;

namespace Incursa.Quic.Tests;

internal static class QuicRfc9001RepeatedKeyUpdateTestSupport
{
    internal static void ConfigureRuntime(QuicConnectionRuntime runtime)
    {
        QuicRfc9001KeyUpdateRetentionTestSupport.ConfigureRuntime(runtime);
    }

    internal static QuicConnectionTransitionResult ReceiveCurrentPhaseAck(
        QuicConnectionRuntime runtime,
        ulong largestAcknowledged,
        long observedAtTicks,
        ulong ackDelay = 0)
    {
        QuicTlsPacketProtectionMaterial currentOpenMaterial =
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value;
        QuicHandshakeFlowCoordinator coordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();
        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            CreateAckPayload(largestAcknowledged, ackDelay),
            currentOpenMaterial,
            keyPhase: (runtime.TlsState.CurrentOneRttKeyPhase & 1U) == 1U,
            out _,
            out byte[] protectedPacket));

        return runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: observedAtTicks,
                QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                protectedPacket),
            nowTicks: observedAtTicks);
    }

    internal static ulong PrepareRepeatedLocalUpdateEligibility(QuicConnectionRuntime runtime)
    {
        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryInstallRuntimeOneRttKeyUpdate(runtime));

        QuicConnectionTransitionResult currentPhasePacketResult =
            QuicRfc9001KeyUpdateRetentionTestSupport.ReceiveCurrentPhaseOnePacket(
                runtime,
                observedAtTicks: Stopwatch.Frequency);
        Assert.True(currentPhasePacketResult.StateChanged);
        Assert.True(runtime.TlsState.RetainedOldOneRttPacketProtectionDiscardAtMicros.HasValue);

        QuicConnectionTransitionResult discardResult =
            QuicRfc9001KeyUpdateRetentionTestSupport.ExpireKeyUpdateRetentionTimer(runtime);
        Assert.True(discardResult.StateChanged);
        Assert.False(runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial.HasValue);
        Assert.False(runtime.TlsState.RetainedOldOneRttProtectPacketProtectionMaterial.HasValue);

        QuicRfc9001KeyUpdateRetentionTestSupport.SeedTrackedOneRttPacket(
            runtime,
            packetNumber: 20,
            sentAtMicros: 100,
            keyPhase: runtime.TlsState.CurrentOneRttKeyPhase);

        QuicConnectionTransitionResult ackResult =
            ReceiveCurrentPhaseAck(runtime, largestAcknowledged: 20, observedAtTicks: Stopwatch.Frequency * 2);
        Assert.True(ackResult.StateChanged);
        Assert.True(runtime.TlsState.CurrentOneRttKeyPhaseAcknowledged);

        return runtime.TlsState.RepeatedLocalOneRttKeyUpdateNotBeforeMicros!.Value;
    }

    internal static void PrepareRepeatedPeerUpdateEligibility(
        QuicConnectionRuntime runtime,
        out QuicTlsPacketProtectionMaterial secondSuccessorOpenMaterial,
        out QuicTlsPacketProtectionMaterial secondSuccessorProtectMaterial)
    {
        ConfigureRuntime(runtime);

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryGetRuntimeSuccessorPhaseOnePacketProtectionMaterial(
            runtime,
            out QuicTlsPacketProtectionMaterial firstSuccessorOpenMaterial,
            out _));

        QuicConnectionTransitionResult firstPeerUpdateResult = ReceivePeerUpdatePacket(
            runtime,
            firstSuccessorOpenMaterial,
            keyPhase: true,
            observedAtTicks: Stopwatch.Frequency,
            QuicRfc9001KeyPhaseTestSupport.CreatePingPayload());
        Assert.True(firstPeerUpdateResult.StateChanged);
        Assert.Equal(1U, runtime.TlsState.CurrentOneRttKeyPhase);
        Assert.True(runtime.TlsState.RetainedOldOneRttPacketProtectionDiscardAtMicros.HasValue);

        QuicConnectionTransitionResult discardResult =
            QuicRfc9001KeyUpdateRetentionTestSupport.ExpireKeyUpdateRetentionTimer(runtime);
        Assert.True(discardResult.StateChanged);
        Assert.False(runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial.HasValue);
        Assert.False(runtime.TlsState.RetainedOldOneRttProtectPacketProtectionMaterial.HasValue);

        QuicRfc9001KeyUpdateRetentionTestSupport.SeedTrackedOneRttPacket(
            runtime,
            packetNumber: 20,
            sentAtMicros: 100,
            keyPhase: runtime.TlsState.CurrentOneRttKeyPhase);

        QuicConnectionTransitionResult ackResult =
            ReceiveCurrentPhaseAck(runtime, largestAcknowledged: 20, observedAtTicks: Stopwatch.Frequency * 2);
        Assert.True(ackResult.StateChanged);
        Assert.True(runtime.TlsState.CurrentOneRttKeyPhaseAcknowledged);

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryGetRuntimeSuccessorPhaseOnePacketProtectionMaterial(
            runtime,
            out secondSuccessorOpenMaterial,
            out secondSuccessorProtectMaterial));
    }

    internal static ulong PreparePhaseTwoCurrentWithOldDiscardedAndAcknowledged(QuicConnectionRuntime runtime)
    {
        ConfigureRuntime(runtime);

        ulong phaseTwoNotBeforeMicros = PrepareRepeatedLocalUpdateEligibility(runtime);
        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryInstallRuntimeRepeatedOneRttKeyUpdate(
            runtime,
            phaseTwoNotBeforeMicros));
        Assert.Equal(2U, runtime.TlsState.CurrentOneRttKeyPhase);

        QuicConnectionTransitionResult currentPhasePacketResult =
            QuicRfc9001KeyUpdateRetentionTestSupport.ReceiveCurrentPhasePacket(
                runtime,
                observedAtTicks: Stopwatch.Frequency * 3L);
        Assert.True(currentPhasePacketResult.StateChanged);
        Assert.True(runtime.TlsState.RetainedOldOneRttPacketProtectionDiscardAtMicros.HasValue);

        QuicConnectionTransitionResult discardResult =
            QuicRfc9001KeyUpdateRetentionTestSupport.ExpireKeyUpdateRetentionTimer(runtime);
        Assert.True(discardResult.StateChanged);
        Assert.False(runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial.HasValue);
        Assert.False(runtime.TlsState.RetainedOldOneRttProtectPacketProtectionMaterial.HasValue);

        QuicRfc9001KeyUpdateRetentionTestSupport.SeedTrackedOneRttPacket(
            runtime,
            packetNumber: 40,
            sentAtMicros: 400,
            keyPhase: runtime.TlsState.CurrentOneRttKeyPhase);

        QuicConnectionTransitionResult ackResult =
            ReceiveCurrentPhaseAck(
                runtime,
                largestAcknowledged: 40,
                observedAtTicks: Stopwatch.Frequency * 4L);
        Assert.True(ackResult.StateChanged);
        Assert.True(runtime.TlsState.CurrentOneRttKeyPhaseAcknowledged);

        return runtime.TlsState.RepeatedLocalOneRttKeyUpdateNotBeforeMicros!.Value;
    }

    internal static ulong PrepareLocalPhaseThreeWithPhaseTwoRetained(QuicConnectionRuntime runtime)
    {
        ulong phaseThreeNotBeforeMicros = PreparePhaseTwoCurrentWithOldDiscardedAndAcknowledged(runtime);

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryInstallRuntimeRepeatedOneRttKeyUpdate(
            runtime,
            phaseThreeNotBeforeMicros));
        Assert.Equal(3U, runtime.TlsState.CurrentOneRttKeyPhase);
        Assert.True(runtime.TlsState.CurrentOneRttKeyPhaseBit);
        Assert.NotNull(runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial);
        Assert.NotNull(runtime.TlsState.RetainedOldOneRttProtectPacketProtectionMaterial);
        Assert.Null(runtime.TlsState.RetainedOldOneRttPacketProtectionDiscardAtMicros);

        return phaseThreeNotBeforeMicros;
    }

    internal static ulong PreparePhaseThreeCurrentWithOldDiscardedAndAcknowledged(QuicConnectionRuntime runtime)
    {
        PrepareLocalPhaseThreeWithPhaseTwoRetained(runtime);

        QuicConnectionTransitionResult currentPhasePacketResult =
            QuicRfc9001KeyUpdateRetentionTestSupport.ReceiveCurrentPhasePacket(
                runtime,
                observedAtTicks: Stopwatch.Frequency * 5L);
        Assert.True(currentPhasePacketResult.StateChanged);
        Assert.True(runtime.TlsState.RetainedOldOneRttPacketProtectionDiscardAtMicros.HasValue);

        QuicConnectionTransitionResult discardResult =
            QuicRfc9001KeyUpdateRetentionTestSupport.ExpireKeyUpdateRetentionTimer(runtime);
        Assert.True(discardResult.StateChanged);
        Assert.False(runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial.HasValue);
        Assert.False(runtime.TlsState.RetainedOldOneRttProtectPacketProtectionMaterial.HasValue);

        QuicRfc9001KeyUpdateRetentionTestSupport.SeedTrackedOneRttPacket(
            runtime,
            packetNumber: 60,
            sentAtMicros: 600,
            keyPhase: runtime.TlsState.CurrentOneRttKeyPhase);

        QuicConnectionTransitionResult ackResult =
            ReceiveCurrentPhaseAck(
                runtime,
                largestAcknowledged: 60,
                observedAtTicks: Stopwatch.Frequency * 6L);
        Assert.True(ackResult.StateChanged);
        Assert.True(runtime.TlsState.CurrentOneRttKeyPhaseAcknowledged);

        return runtime.TlsState.RepeatedLocalOneRttKeyUpdateNotBeforeMicros!.Value;
    }

    internal static ulong PrepareLocalPhaseFourWithPhaseThreeRetained(QuicConnectionRuntime runtime)
    {
        ulong phaseFourNotBeforeMicros = PreparePhaseThreeCurrentWithOldDiscardedAndAcknowledged(runtime);

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryInstallRuntimeRepeatedOneRttKeyUpdate(
            runtime,
            phaseFourNotBeforeMicros));
        Assert.Equal(4U, runtime.TlsState.CurrentOneRttKeyPhase);
        Assert.False(runtime.TlsState.CurrentOneRttKeyPhaseBit);
        Assert.NotNull(runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial);
        Assert.NotNull(runtime.TlsState.RetainedOldOneRttProtectPacketProtectionMaterial);
        Assert.Null(runtime.TlsState.RetainedOldOneRttPacketProtectionDiscardAtMicros);

        return phaseFourNotBeforeMicros;
    }

    internal static QuicConnectionTransitionResult ReceivePeerUpdatePacket(
        QuicConnectionRuntime runtime,
        QuicTlsPacketProtectionMaterial openMaterial,
        bool keyPhase,
        long observedAtTicks,
        byte[] payload)
    {
        byte[] protectedPacket = QuicRfc9001KeyPhaseTestSupport.BuildProtectedApplicationPacket(
            openMaterial,
            keyPhase,
            payload);

        return runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: observedAtTicks,
                QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                protectedPacket),
            nowTicks: observedAtTicks);
    }

    private static byte[] CreateAckPayload(ulong largestAcknowledged, ulong ackDelay)
    {
        byte[] payload = new byte[64];
        Assert.True(QuicFrameCodec.TryFormatAckFrame(
            new QuicAckFrame
            {
                FrameType = 0x02,
                LargestAcknowledged = largestAcknowledged,
                AckDelay = ackDelay,
                FirstAckRange = 0,
                AdditionalRanges = [],
            },
            payload,
            out int bytesWritten));
        Assert.True(bytesWritten > 0);
        if (bytesWritten < payload.Length)
        {
            payload.AsSpan(bytesWritten).Fill(0);
        }

        return payload;
    }
}
