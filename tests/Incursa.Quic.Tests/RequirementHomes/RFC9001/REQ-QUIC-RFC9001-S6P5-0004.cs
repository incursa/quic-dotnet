using System.Diagnostics;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual trace slice">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S6P5-0004">An endpoint SHOULD retain old read keys for no more than three times the PTO after receiving a packet protected with the new keys.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9001-S6P5-0004")]
public sealed class REQ_QUIC_RFC9001_S6P5_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveClientRuntimeArmsTheOldReadKeyRetentionTimerFromTheFirstNewKeyPacket()
    {
        AssertRuntimeArmsTheOldReadKeyRetentionTimer(
            QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveServerRuntimeArmsTheOldReadKeyRetentionTimerFromTheFirstNewKeyPacket()
    {
        AssertRuntimeArmsTheOldReadKeyRetentionTimer(
            () => QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ActiveClientRuntimeDoesNotExtendTheRetentionTimerAfterAnotherNewKeyPacket()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001KeyUpdateRetentionTestSupport.ConfigureRuntime(runtime);

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryInstallRuntimeOneRttKeyUpdate(runtime));

        long firstObservedAtTicks = Stopwatch.Frequency;
        QuicConnectionTransitionResult firstResult =
            QuicRfc9001KeyUpdateRetentionTestSupport.ReceiveCurrentPhaseOnePacket(runtime, firstObservedAtTicks);

        Assert.True(firstResult.StateChanged);
        long firstDueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.KeyUpdateRetention)!.Value;
        ulong firstDiscardAtMicros = runtime.TlsState.RetainedOldOneRttPacketProtectionDiscardAtMicros!.Value;

        QuicConnectionTransitionResult secondResult =
            QuicRfc9001KeyUpdateRetentionTestSupport.ReceiveCurrentPhaseOnePacket(runtime, firstObservedAtTicks + Stopwatch.Frequency);

        Assert.True(secondResult.StateChanged);
        Assert.Equal(firstDueTicks, runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.KeyUpdateRetention));
        Assert.Equal(firstDiscardAtMicros, runtime.TlsState.RetainedOldOneRttPacketProtectionDiscardAtMicros);
        Assert.NotNull(runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial);
        Assert.NotNull(runtime.TlsState.RetainedOldOneRttProtectPacketProtectionMaterial);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveClientRuntimeArmsThePhaseOneRetentionTimerAfterRepeatedLocalKeyUpdate()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001RepeatedKeyUpdateTestSupport.ConfigureRuntime(runtime);

        ulong notBeforeMicros = QuicRfc9001RepeatedKeyUpdateTestSupport.PrepareRepeatedLocalUpdateEligibility(runtime);
        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryInstallRuntimeRepeatedOneRttKeyUpdate(runtime, notBeforeMicros));
        Assert.Equal(2U, runtime.TlsState.CurrentOneRttKeyPhase);
        Assert.Null(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.KeyUpdateRetention));

        long observedAtTicks = Stopwatch.Frequency * 3L;
        QuicConnectionTransitionResult result =
            QuicRfc9001KeyUpdateRetentionTestSupport.ReceiveCurrentPhasePacket(runtime, observedAtTicks);

        Assert.True(result.StateChanged);
        AssertRetainedPhaseOneTimer(runtime, observedAtTicks);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveClientRuntimeArmsThePhaseOneRetentionTimerAfterRepeatedPeerKeyUpdate()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001RepeatedKeyUpdateTestSupport.PrepareRepeatedPeerUpdateEligibility(
            runtime,
            out QuicTlsPacketProtectionMaterial secondSuccessorOpenMaterial,
            out _);

        long observedAtTicks = Stopwatch.Frequency * 3L;
        QuicConnectionTransitionResult result = QuicRfc9001RepeatedKeyUpdateTestSupport.ReceivePeerUpdatePacket(
            runtime,
            secondSuccessorOpenMaterial,
            keyPhase: false,
            observedAtTicks,
            QuicRfc9001KeyPhaseTestSupport.CreatePingPayload());

        Assert.True(result.StateChanged);
        Assert.Equal(2U, runtime.TlsState.CurrentOneRttKeyPhase);
        AssertRetainedPhaseOneTimer(runtime, observedAtTicks);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ActiveClientRuntimeDoesNotExtendThePhaseOneRetentionTimerAfterAnotherPhaseTwoPacket()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001RepeatedKeyUpdateTestSupport.ConfigureRuntime(runtime);

        ulong notBeforeMicros = QuicRfc9001RepeatedKeyUpdateTestSupport.PrepareRepeatedLocalUpdateEligibility(runtime);
        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryInstallRuntimeRepeatedOneRttKeyUpdate(runtime, notBeforeMicros));

        long firstObservedAtTicks = Stopwatch.Frequency * 3L;
        QuicConnectionTransitionResult firstResult =
            QuicRfc9001KeyUpdateRetentionTestSupport.ReceiveCurrentPhasePacket(runtime, firstObservedAtTicks);

        Assert.True(firstResult.StateChanged);
        long firstDueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.KeyUpdateRetention)!.Value;
        ulong firstDiscardAtMicros = runtime.TlsState.RetainedOldOneRttPacketProtectionDiscardAtMicros!.Value;

        QuicConnectionTransitionResult secondResult =
            QuicRfc9001KeyUpdateRetentionTestSupport.ReceiveCurrentPhasePacket(
                runtime,
                firstObservedAtTicks + Stopwatch.Frequency);

        Assert.True(secondResult.StateChanged);
        Assert.Equal(firstDueTicks, runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.KeyUpdateRetention));
        Assert.Equal(firstDiscardAtMicros, runtime.TlsState.RetainedOldOneRttPacketProtectionDiscardAtMicros);
        Assert.Equal(1U, runtime.TlsState.RetainedOldOneRttPacketProtectionKeyPhase);
        Assert.NotNull(runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial);
        Assert.NotNull(runtime.TlsState.RetainedOldOneRttProtectPacketProtectionMaterial);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveClientRuntimeArmsThePhaseTwoRetentionTimerAfterPhaseThreeLocalKeyUpdate()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001RepeatedKeyUpdateTestSupport.PrepareLocalPhaseThreeWithPhaseTwoRetained(runtime);

        Assert.Equal(3U, runtime.TlsState.CurrentOneRttKeyPhase);
        Assert.Null(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.KeyUpdateRetention));

        long observedAtTicks = Stopwatch.Frequency * 5L;
        QuicConnectionTransitionResult result =
            QuicRfc9001KeyUpdateRetentionTestSupport.ReceiveCurrentPhasePacket(runtime, observedAtTicks);

        Assert.True(result.StateChanged);
        AssertRetainedPhaseTwoTimer(runtime, observedAtTicks);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ActiveClientRuntimeDoesNotExtendThePhaseTwoRetentionTimerAfterAnotherPhaseThreePacket()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001RepeatedKeyUpdateTestSupport.PrepareLocalPhaseThreeWithPhaseTwoRetained(runtime);

        long firstObservedAtTicks = Stopwatch.Frequency * 5L;
        QuicConnectionTransitionResult firstResult =
            QuicRfc9001KeyUpdateRetentionTestSupport.ReceiveCurrentPhasePacket(runtime, firstObservedAtTicks);

        Assert.True(firstResult.StateChanged);
        long firstDueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.KeyUpdateRetention)!.Value;
        ulong firstDiscardAtMicros = runtime.TlsState.RetainedOldOneRttPacketProtectionDiscardAtMicros!.Value;

        QuicConnectionTransitionResult secondResult =
            QuicRfc9001KeyUpdateRetentionTestSupport.ReceiveCurrentPhasePacket(
                runtime,
                firstObservedAtTicks + Stopwatch.Frequency);

        Assert.True(secondResult.StateChanged);
        Assert.Equal(firstDueTicks, runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.KeyUpdateRetention));
        Assert.Equal(firstDiscardAtMicros, runtime.TlsState.RetainedOldOneRttPacketProtectionDiscardAtMicros);
        Assert.Equal(2U, runtime.TlsState.RetainedOldOneRttPacketProtectionKeyPhase);
        Assert.NotNull(runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial);
        Assert.NotNull(runtime.TlsState.RetainedOldOneRttProtectPacketProtectionMaterial);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveClientRuntimeArmsThePhaseThreeRetentionTimerAfterPhaseFourLocalKeyUpdate()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001RepeatedKeyUpdateTestSupport.PrepareLocalPhaseFourWithPhaseThreeRetained(runtime);

        Assert.Equal(4U, runtime.TlsState.CurrentOneRttKeyPhase);
        Assert.Null(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.KeyUpdateRetention));

        long observedAtTicks = Stopwatch.Frequency * 7L;
        QuicConnectionTransitionResult result =
            QuicRfc9001KeyUpdateRetentionTestSupport.ReceiveCurrentPhasePacket(runtime, observedAtTicks);

        Assert.True(result.StateChanged);
        AssertRetainedPhaseThreeTimer(runtime, observedAtTicks);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ActiveClientRuntimeDoesNotExtendThePhaseThreeRetentionTimerAfterAnotherPhaseFourPacket()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001RepeatedKeyUpdateTestSupport.PrepareLocalPhaseFourWithPhaseThreeRetained(runtime);

        long firstObservedAtTicks = Stopwatch.Frequency * 7L;
        QuicConnectionTransitionResult firstResult =
            QuicRfc9001KeyUpdateRetentionTestSupport.ReceiveCurrentPhasePacket(runtime, firstObservedAtTicks);

        Assert.True(firstResult.StateChanged);
        long firstDueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.KeyUpdateRetention)!.Value;
        ulong firstDiscardAtMicros = runtime.TlsState.RetainedOldOneRttPacketProtectionDiscardAtMicros!.Value;

        QuicConnectionTransitionResult secondResult =
            QuicRfc9001KeyUpdateRetentionTestSupport.ReceiveCurrentPhasePacket(
                runtime,
                firstObservedAtTicks + Stopwatch.Frequency);

        Assert.True(secondResult.StateChanged);
        Assert.Equal(firstDueTicks, runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.KeyUpdateRetention));
        Assert.Equal(firstDiscardAtMicros, runtime.TlsState.RetainedOldOneRttPacketProtectionDiscardAtMicros);
        Assert.Equal(3U, runtime.TlsState.RetainedOldOneRttPacketProtectionKeyPhase);
        Assert.NotNull(runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial);
        Assert.NotNull(runtime.TlsState.RetainedOldOneRttProtectPacketProtectionMaterial);
    }

    private static void AssertRuntimeArmsTheOldReadKeyRetentionTimer(Func<QuicConnectionRuntime> runtimeFactory)
    {
        using QuicConnectionRuntime runtime = runtimeFactory();
        QuicRfc9001KeyUpdateRetentionTestSupport.ConfigureRuntime(runtime);

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryInstallRuntimeOneRttKeyUpdate(runtime));
        Assert.NotNull(runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial);
        Assert.NotNull(runtime.TlsState.RetainedOldOneRttProtectPacketProtectionMaterial);
        Assert.Null(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.KeyUpdateRetention));

        long observedAtTicks = Stopwatch.Frequency;
        QuicConnectionTransitionResult result =
            QuicRfc9001KeyUpdateRetentionTestSupport.ReceiveCurrentPhaseOnePacket(runtime, observedAtTicks);

        Assert.True(result.StateChanged);
        long dueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.KeyUpdateRetention)!.Value;
        Assert.True(dueTicks > observedAtTicks);

        ulong observedAtMicros = QuicRfc9001KeyUpdateRetentionTestSupport.ConvertTicksToMicros(observedAtTicks);
        ulong expectedRetentionMicros = Math.Max(runtime.CurrentProbeTimeoutMicros, 1UL) * 3UL;
        ulong expectedDiscardAtMicros = observedAtMicros + expectedRetentionMicros;

        Assert.Equal(expectedDiscardAtMicros, runtime.TlsState.RetainedOldOneRttPacketProtectionDiscardAtMicros);
        Assert.Equal(0U, runtime.TlsState.RetainedOldOneRttPacketProtectionKeyPhase);
        Assert.NotNull(runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial);
        Assert.NotNull(runtime.TlsState.RetainedOldOneRttProtectPacketProtectionMaterial);
    }

    private static void AssertRetainedPhaseOneTimer(QuicConnectionRuntime runtime, long observedAtTicks)
    {
        AssertRetainedTimer(runtime, observedAtTicks, expectedRetainedKeyPhase: 1);
    }

    private static void AssertRetainedPhaseTwoTimer(QuicConnectionRuntime runtime, long observedAtTicks)
    {
        AssertRetainedTimer(runtime, observedAtTicks, expectedRetainedKeyPhase: 2);
    }

    private static void AssertRetainedPhaseThreeTimer(QuicConnectionRuntime runtime, long observedAtTicks)
    {
        AssertRetainedTimer(runtime, observedAtTicks, expectedRetainedKeyPhase: 3);
    }

    private static void AssertRetainedTimer(
        QuicConnectionRuntime runtime,
        long observedAtTicks,
        uint expectedRetainedKeyPhase)
    {
        long dueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.KeyUpdateRetention)!.Value;
        Assert.True(dueTicks > observedAtTicks);

        ulong observedAtMicros = QuicRfc9001KeyUpdateRetentionTestSupport.ConvertTicksToMicros(observedAtTicks);
        ulong expectedRetentionMicros = Math.Max(runtime.CurrentProbeTimeoutMicros, 1UL) * 3UL;
        ulong expectedDiscardAtMicros = observedAtMicros + expectedRetentionMicros;

        Assert.Equal(expectedDiscardAtMicros, runtime.TlsState.RetainedOldOneRttPacketProtectionDiscardAtMicros);
        Assert.Equal(expectedRetainedKeyPhase, runtime.TlsState.RetainedOldOneRttPacketProtectionKeyPhase);
        Assert.NotNull(runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial);
        Assert.NotNull(runtime.TlsState.RetainedOldOneRttProtectPacketProtectionMaterial);
    }
}
