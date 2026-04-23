using System.Diagnostics;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual trace slice">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S6P5-0003">Endpoints SHOULD wait three times the PTO before initiating a key update after receiving the acknowledgment that confirms the previous key update.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9001-S6P5-0003")]
public sealed class REQ_QUIC_RFC9001_S6P5_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveClientRuntimeArmsAThreePtoCooldownAfterAcknowledgingTheCurrentKeyPhase()
    {
        AssertRuntimeArmsAThreePtoCooldownAfterAcknowledgingTheCurrentKeyPhase(
            QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveServerRuntimeArmsAThreePtoCooldownAfterAcknowledgingTheCurrentKeyPhase()
    {
        AssertRuntimeArmsAThreePtoCooldownAfterAcknowledgingTheCurrentKeyPhase(
            () => QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ActiveClientRuntimeDoesNotAllowARepeatedLocalKeyUpdateBeforeTheCurrentKeyPhaseIsAcknowledged()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001RepeatedKeyUpdateTestSupport.ConfigureRuntime(runtime);

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryInstallRuntimeOneRttKeyUpdate(runtime));

        ulong queryAtMicros = QuicRfc9001KeyUpdateRetentionTestSupport.ConvertTicksToMicros(Stopwatch.Frequency);
        Assert.False(runtime.TlsState.CurrentOneRttKeyPhaseAcknowledged);
        Assert.Null(runtime.TlsState.RepeatedLocalOneRttKeyUpdateNotBeforeMicros);
        Assert.False(runtime.TlsState.CanInitiateRepeatedLocalOneRttKeyUpdate(queryAtMicros));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ActiveClientRuntimeDoesNotArmTheRepeatedUpdateCooldownWhenOnlyAnOldPhasePacketIsAcknowledged()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001RepeatedKeyUpdateTestSupport.ConfigureRuntime(runtime);

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryInstallRuntimeOneRttKeyUpdate(runtime));
        QuicRfc9001KeyUpdateRetentionTestSupport.SeedTrackedOneRttPacket(runtime, packetNumber: 10, sentAtMicros: 100, keyPhase: 0);

        QuicConnectionTransitionResult result =
            QuicRfc9001RepeatedKeyUpdateTestSupport.ReceiveCurrentPhaseAck(runtime, largestAcknowledged: 10, observedAtTicks: Stopwatch.Frequency);

        Assert.True(result.StateChanged);
        Assert.False(runtime.TlsState.CurrentOneRttKeyPhaseAcknowledged);
        Assert.Null(runtime.TlsState.RepeatedLocalOneRttKeyUpdateNotBeforeMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ActiveClientRuntimeDoesNotExtendTheRepeatedUpdateCooldownAfterDuplicateAcknowledgments()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001RepeatedKeyUpdateTestSupport.ConfigureRuntime(runtime);

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryInstallRuntimeOneRttKeyUpdate(runtime));
        QuicRfc9001KeyUpdateRetentionTestSupport.SeedTrackedOneRttPacket(runtime, packetNumber: 10, sentAtMicros: 100, keyPhase: 1);

        _ = QuicRfc9001RepeatedKeyUpdateTestSupport.ReceiveCurrentPhaseAck(runtime, largestAcknowledged: 10, observedAtTicks: Stopwatch.Frequency);
        ulong firstNotBeforeMicros = runtime.TlsState.RepeatedLocalOneRttKeyUpdateNotBeforeMicros!.Value;

        _ = QuicRfc9001RepeatedKeyUpdateTestSupport.ReceiveCurrentPhaseAck(runtime, largestAcknowledged: 10, observedAtTicks: Stopwatch.Frequency * 2);

        Assert.True(runtime.TlsState.CurrentOneRttKeyPhaseAcknowledged);
        Assert.Equal(firstNotBeforeMicros, runtime.TlsState.RepeatedLocalOneRttKeyUpdateNotBeforeMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzRepeatedLocalKeyUpdateCooldown_RandomizedAcknowledgmentTimingKeepsTheGateClosedUntilThreePtosExpire()
    {
        Random random = new(unchecked((int)0x9001_6503));

        for (int iteration = 0; iteration < 32; iteration++)
        {
            using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
            QuicRfc9001RepeatedKeyUpdateTestSupport.ConfigureRuntime(runtime);

            Assert.True(QuicRfc9001KeyPhaseTestSupport.TryInstallRuntimeOneRttKeyUpdate(runtime));
            ulong packetNumber = (ulong)(100 + iteration);
            QuicRfc9001KeyUpdateRetentionTestSupport.SeedTrackedOneRttPacket(
                runtime,
                packetNumber,
                sentAtMicros: (ulong)(1_000 + iteration),
                keyPhase: 1);

            long observedAtTicks = Stopwatch.Frequency + iteration + 1;
            ulong ackDelay = (ulong)random.Next(0, 64);
            QuicConnectionTransitionResult result =
                QuicRfc9001RepeatedKeyUpdateTestSupport.ReceiveCurrentPhaseAck(
                    runtime,
                    packetNumber,
                    observedAtTicks,
                    ackDelay);

            ulong expectedNotBeforeMicros = ComputeExpectedNotBeforeMicros(
                QuicRfc9001KeyUpdateRetentionTestSupport.ConvertTicksToMicros(observedAtTicks),
                runtime.CurrentProbeTimeoutMicros);

            Assert.True(result.StateChanged);
            Assert.True(runtime.TlsState.CurrentOneRttKeyPhaseAcknowledged);
            Assert.Equal(expectedNotBeforeMicros, runtime.TlsState.RepeatedLocalOneRttKeyUpdateNotBeforeMicros);
            Assert.False(runtime.TlsState.CanInitiateRepeatedLocalOneRttKeyUpdate(expectedNotBeforeMicros - 1));
            Assert.True(runtime.TlsState.CanInitiateRepeatedLocalOneRttKeyUpdate(expectedNotBeforeMicros + (ulong)random.Next(0, 32)));
        }
    }

    private static void AssertRuntimeArmsAThreePtoCooldownAfterAcknowledgingTheCurrentKeyPhase(
        Func<QuicConnectionRuntime> runtimeFactory)
    {
        using QuicConnectionRuntime runtime = runtimeFactory();
        QuicRfc9001RepeatedKeyUpdateTestSupport.ConfigureRuntime(runtime);

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryInstallRuntimeOneRttKeyUpdate(runtime));
        QuicRfc9001KeyUpdateRetentionTestSupport.SeedTrackedOneRttPacket(runtime, packetNumber: 10, sentAtMicros: 100, keyPhase: 1);

        long observedAtTicks = Stopwatch.Frequency;
        QuicConnectionTransitionResult result =
            QuicRfc9001RepeatedKeyUpdateTestSupport.ReceiveCurrentPhaseAck(runtime, largestAcknowledged: 10, observedAtTicks: observedAtTicks);

        ulong expectedNotBeforeMicros = ComputeExpectedNotBeforeMicros(
            QuicRfc9001KeyUpdateRetentionTestSupport.ConvertTicksToMicros(observedAtTicks),
            runtime.CurrentProbeTimeoutMicros);

        Assert.True(result.StateChanged);
        Assert.True(runtime.TlsState.CurrentOneRttKeyPhaseAcknowledged);
        Assert.Equal(expectedNotBeforeMicros, runtime.TlsState.RepeatedLocalOneRttKeyUpdateNotBeforeMicros);
        Assert.False(runtime.TlsState.CanInitiateRepeatedLocalOneRttKeyUpdate(expectedNotBeforeMicros - 1));
        Assert.True(runtime.TlsState.CanInitiateRepeatedLocalOneRttKeyUpdate(expectedNotBeforeMicros));
    }

    private static ulong ComputeExpectedNotBeforeMicros(ulong acknowledgedAtMicros, ulong probeTimeoutMicros)
    {
        ulong cooldownMicros = Math.Max(probeTimeoutMicros, 1UL) * 3UL;
        ulong sum = acknowledgedAtMicros + cooldownMicros;
        return sum < acknowledgedAtMicros ? ulong.MaxValue : sum;
    }
}
