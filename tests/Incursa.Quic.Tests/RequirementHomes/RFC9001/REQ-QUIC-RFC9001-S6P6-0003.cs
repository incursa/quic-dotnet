using System.Diagnostics;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual trace slice">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S6P6-0003">Endpoints MUST initiate a key update before sending more protected packets than the selected AEAD confidentiality limit permits.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9001-S6P6-0003")]
public sealed class REQ_QUIC_RFC9001_S6P6_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AeadLimitPolicyRequestsKeyUpdateWhenConfidentialityLimitBlocksFurtherProtection()
    {
        QuicAeadKeyLifecycle keyLifecycle = CreateActiveLifecycle(confidentialityLimit: 1, integrityLimit: 16);

        Assert.True(keyLifecycle.TryUseForProtection());

        QuicAeadLimitDecision decision = QuicAeadLimitPolicy.EvaluateProtectionUse(
            keyLifecycle,
            keyUpdatePossible: true);

        Assert.Equal(QuicAeadLimitAction.InitiateKeyUpdate, decision.Action);
        Assert.Null(decision.TransportErrorCode);
        Assert.False(decision.RequiresConnectionStop);
        Assert.False(keyLifecycle.TryUseForProtection());
        Assert.Equal(1d, keyLifecycle.ProtectedPacketCount);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task RuntimeSendPathInstallsFirstKeyUpdateBeforeProtectingBeyondConfidentialityLimit()
    {
        using QuicConnectionRuntime runtime = CreateConfirmedClientRuntimeWithAeadLimitHeadroom();
        QuicAeadKeyLifecycle originalProtectLifecycle =
            QuicRfc9001KeyUpdateRetentionTestSupport.ReplaceCurrentOneRttProtectKeyLifecycleForTest(runtime);
        List<QuicConnectionEffect> outboundEffects = [];
        DispatchRuntimeEvents(runtime, outboundEffects);

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        AcknowledgeTrackedPackets(runtime);
        outboundEffects.Clear();

        Assert.NotNull(originalProtectLifecycle);
        byte[] payload = new byte[32];
        while (originalProtectLifecycle.ProtectedPacketCount < QuicRfc9001KeyUpdateRetentionTestSupport.RuntimeTestConfidentialityLimitPackets)
        {
            await stream.WriteAsync(payload, 0, payload.Length);
            AcknowledgeTrackedPackets(runtime);
            outboundEffects.Clear();
        }

        Assert.False(runtime.TlsState.KeyUpdateInstalled);
        Assert.Equal(0U, runtime.TlsState.CurrentOneRttKeyPhase);
        Assert.True(originalProtectLifecycle.HasReachedConfidentialityLimit);

        await stream.WriteAsync(payload, 0, payload.Length);

        Assert.True(runtime.TlsState.KeyUpdateInstalled);
        Assert.Equal(1U, runtime.TlsState.CurrentOneRttKeyPhase);
        Assert.Same(originalProtectLifecycle, runtime.TlsState.RetainedOldOneRttProtectKeyLifecycle);
        Assert.Equal(QuicRfc9001KeyUpdateRetentionTestSupport.RuntimeTestConfidentialityLimitPackets, runtime.TlsState.RetainedOldOneRttProtectKeyLifecycle!.ProtectedPacketCount);
        Assert.Equal(1d, runtime.TlsState.CurrentOneRttProtectKeyLifecycle!.ProtectedPacketCount);
        Assert.Contains(outboundEffects, effect => effect is QuicConnectionSendDatagramEffect);
        Assert.DoesNotContain(outboundEffects, effect => effect is QuicConnectionDiscardConnectionStateEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task RuntimeSendPathInstallsRepeatedKeyUpdateBeforeProtectingBeyondRepeatedConfidentialityLimit()
    {
        FakeMonotonicClock clock = new(0);
        using QuicConnectionRuntime runtime = CreateConfirmedClientRuntimeWithAeadLimitHeadroom(clock);
        QuicRfc9001RepeatedKeyUpdateTestSupport.ConfigureRuntime(runtime);
        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryInstallRuntimeOneRttKeyUpdate(runtime));
        Assert.True(runtime.TlsState.TryDiscardRetainedOneRttKeyUpdateMaterial());
        Assert.True(runtime.TlsState.TryRecordCurrentOneRttKeyPhaseAcknowledgment(
            acknowledgedAtMicros: 1_000_000,
            probeTimeoutMicros: 25_000));
        ulong notBeforeMicros = runtime.TlsState.RepeatedLocalOneRttKeyUpdateNotBeforeMicros!.Value;
        clock.Advance(Stopwatch.Frequency * 2L);
        QuicAeadKeyLifecycle phaseOneProtectLifecycle =
            QuicRfc9001KeyUpdateRetentionTestSupport.ReplaceCurrentOneRttProtectKeyLifecycleForTest(runtime);

        List<QuicConnectionEffect> outboundEffects = [];
        DispatchRuntimeEvents(runtime, outboundEffects);

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        AcknowledgeTrackedPackets(runtime);
        outboundEffects.Clear();

        byte[] payload = new byte[32];
        Assert.Equal(1U, runtime.TlsState.CurrentOneRttKeyPhase);
        Assert.True(runtime.TlsState.CurrentOneRttKeyPhaseAcknowledged);
        Assert.True(runtime.TlsState.CanInitiateRepeatedLocalOneRttKeyUpdate(notBeforeMicros));

        await ProtectUntilConfidentialityLimitAsync(stream, runtime, outboundEffects, phaseOneProtectLifecycle, payload);

        Assert.Equal(1U, runtime.TlsState.CurrentOneRttKeyPhase);
        Assert.True(phaseOneProtectLifecycle.HasReachedConfidentialityLimit);

        await stream.WriteAsync(payload, 0, payload.Length);

        Assert.Equal(2U, runtime.TlsState.CurrentOneRttKeyPhase);
        Assert.Same(phaseOneProtectLifecycle, runtime.TlsState.RetainedOldOneRttProtectKeyLifecycle);
        Assert.Equal(QuicRfc9001KeyUpdateRetentionTestSupport.RuntimeTestConfidentialityLimitPackets, runtime.TlsState.RetainedOldOneRttProtectKeyLifecycle!.ProtectedPacketCount);
        Assert.Equal(1d, runtime.TlsState.CurrentOneRttProtectKeyLifecycle!.ProtectedPacketCount);
        Assert.Contains(outboundEffects, effect => effect is QuicConnectionSendDatagramEffect);
        Assert.DoesNotContain(outboundEffects, effect => effect is QuicConnectionDiscardConnectionStateEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AeadLimitPolicyContinuesBeforeConfidentialityLimitIsReached()
    {
        QuicAeadKeyLifecycle keyLifecycle = CreateActiveLifecycle(confidentialityLimit: 2, integrityLimit: 16);

        Assert.True(keyLifecycle.TryUseForProtection());

        QuicAeadLimitDecision decision = QuicAeadLimitPolicy.EvaluateProtectionUse(
            keyLifecycle,
            keyUpdatePossible: true);

        Assert.Equal(QuicAeadLimitAction.Continue, decision.Action);
        Assert.Null(decision.TransportErrorCode);
        Assert.False(decision.RequiresConnectionStop);
        Assert.True(keyLifecycle.CanProtect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzConfidentialityLimitPolicy_RandomizedLimitsRequestKeyUpdateBeforeExcessProtection()
    {
        Random random = new(unchecked((int)0x9001_6603));

        for (int iteration = 0; iteration < 64; iteration++)
        {
            int confidentialityLimit = random.Next(1, 24);
            QuicAeadKeyLifecycle keyLifecycle = CreateActiveLifecycle(confidentialityLimit, integrityLimit: 128);

            for (int packet = 0; packet < confidentialityLimit; packet++)
            {
                Assert.True(keyLifecycle.TryUseForProtection());
            }

            QuicAeadLimitDecision decision = QuicAeadLimitPolicy.EvaluateProtectionUse(
                keyLifecycle,
                keyUpdatePossible: true);

            Assert.Equal(QuicAeadLimitAction.InitiateKeyUpdate, decision.Action);
            Assert.Equal((double)confidentialityLimit, keyLifecycle.ProtectedPacketCount);
            Assert.False(keyLifecycle.TryUseForProtection());
            Assert.Equal((double)confidentialityLimit, keyLifecycle.ProtectedPacketCount);
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzRepeatedConfidentialityLimitPolicy_UsesRepeatedLocalUpdateGate()
    {
        Random random = new(unchecked((int)0x9001_6633));

        for (int iteration = 0; iteration < 16; iteration++)
        {
            using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
            QuicRfc9001RepeatedKeyUpdateTestSupport.ConfigureRuntime(runtime);
            ulong notBeforeMicros = QuicRfc9001RepeatedKeyUpdateTestSupport.PrepareRepeatedLocalUpdateEligibility(runtime);
            ulong nowMicros = iteration % 2 == 0
                ? notBeforeMicros - (ulong)random.Next(1, 32)
                : notBeforeMicros + (ulong)random.Next(0, 32);

            int confidentialityLimit = random.Next(1, 24);
            QuicAeadKeyLifecycle keyLifecycle = CreateActiveLifecycle(confidentialityLimit, integrityLimit: 128);
            for (int packet = 0; packet < confidentialityLimit; packet++)
            {
                Assert.True(keyLifecycle.TryUseForProtection());
            }

            bool repeatedUpdatePossible = runtime.TlsState.CanInitiateRepeatedLocalOneRttKeyUpdate(nowMicros);
            QuicAeadLimitDecision decision = QuicAeadLimitPolicy.EvaluateProtectionUse(
                keyLifecycle,
                repeatedUpdatePossible);

            if (nowMicros >= notBeforeMicros)
            {
                Assert.True(repeatedUpdatePossible);
                Assert.Equal(QuicAeadLimitAction.InitiateKeyUpdate, decision.Action);
                Assert.Null(decision.TransportErrorCode);
            }
            else
            {
                Assert.False(repeatedUpdatePossible);
                Assert.Equal(QuicAeadLimitAction.StopUsingConnection, decision.Action);
                Assert.Equal(QuicTransportErrorCode.AeadLimitReached, decision.TransportErrorCode);
            }
        }
    }

    private static QuicAeadKeyLifecycle CreateActiveLifecycle(int confidentialityLimit, int integrityLimit)
    {
        QuicAeadKeyLifecycle keyLifecycle = new(new QuicAeadUsageLimits(confidentialityLimit, integrityLimit));
        Assert.True(keyLifecycle.TryActivate());
        return keyLifecycle;
    }

    private static QuicConnectionRuntime CreateConfirmedClientRuntimeWithAeadLimitHeadroom(IMonotonicClock? clock = null)
    {
        return QuicS13ApplicationSendDelayTestSupport.CreateConfirmedClientRuntimeWithValidatedActivePath(
            clock,
            connectionReceiveLimit: 16_384,
            connectionSendLimit: 16_384,
            localBidirectionalSendLimit: 16_384,
            localBidirectionalReceiveLimit: 16_384,
            peerBidirectionalReceiveLimit: 16_384);
    }

    private static async Task ProtectUntilConfidentialityLimitAsync(
        QuicStream stream,
        QuicConnectionRuntime runtime,
        List<QuicConnectionEffect> outboundEffects,
        QuicAeadKeyLifecycle keyLifecycle,
        byte[] payload)
    {
        while (keyLifecycle.ProtectedPacketCount < QuicRfc9001KeyUpdateRetentionTestSupport.RuntimeTestConfidentialityLimitPackets)
        {
            await stream.WriteAsync(payload, 0, payload.Length);
            AcknowledgeTrackedPackets(runtime);
            outboundEffects.Clear();
        }
    }

    private static void DispatchRuntimeEvents(
        QuicConnectionRuntime runtime,
        List<QuicConnectionEffect> outboundEffects)
    {
        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });
    }

    private static void AcknowledgeTrackedPackets(QuicConnectionRuntime runtime)
    {
        foreach (KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> sentPacket in runtime.SendRuntime.SentPackets.ToArray())
        {
            Assert.True(runtime.SendRuntime.TryAcknowledgePacket(
                sentPacket.Key.PacketNumberSpace,
                sentPacket.Key.PacketNumber,
                handshakeConfirmed: true));
        }
    }
}
