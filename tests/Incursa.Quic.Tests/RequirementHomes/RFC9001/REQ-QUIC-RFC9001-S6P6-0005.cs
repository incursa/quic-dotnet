namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual trace slice">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S6P6-0005">If a key update is not possible or integrity limits are reached, an endpoint MUST send only stateless resets in response to received packets.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9001-S6P6-0005")]
public sealed class REQ_QUIC_RFC9001_S6P6_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AeadLimitPolicyAllowsOnlyStatelessResetsAfterConnectionStoppedForAeadLimit()
    {
        QuicAeadKeyLifecycle keyLifecycle = CreateActiveLifecycle(confidentialityLimit: 16, integrityLimit: 16);

        QuicAeadLimitDecision decision = QuicAeadLimitPolicy.EvaluateReceivedPacketResponse(
            keyLifecycle,
            connectionStoppedForAeadLimit: true);

        Assert.Equal(QuicAeadLimitAction.SendOnlyStatelessReset, decision.Action);
        Assert.Equal(QuicTransportErrorCode.AeadLimitReached, decision.TransportErrorCode);
        Assert.True(decision.RequiresConnectionStop);
        Assert.True(decision.AllowsOnlyStatelessReset);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RuntimeOpenPathDiscardsConnectionWhenIntegrityLimitIsReached()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime();
        QuicRfc9001KeyUpdateRetentionTestSupport.ConfigureRuntime(runtime);

        QuicAeadKeyLifecycle openLifecycle = runtime.TlsState.CurrentOneRttOpenKeyLifecycle!;
        Assert.NotNull(openLifecycle);
        QuicHandshakeFlowCoordinator peerCoordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();
        byte[] paddingPayload = [0x00];

        QuicConnectionTransitionResult result = default;
        for (int packet = 0; packet < 128; packet++)
        {
            Assert.True(peerCoordinator.TryBuildProtectedApplicationDataPacket(
                paddingPayload,
                runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value,
                keyPhase: false,
                out _,
                out byte[] protectedPacket));

            result = runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: packet + 1,
                    QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                    protectedPacket),
                nowTicks: packet + 1);

            if (packet < 127)
            {
                Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
                Assert.Equal(packet + 1d, openLifecycle.OpenedPacketCount);
                Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionDiscardConnectionStateEffect);
            }
        }

        Assert.True(result.StateChanged);
        Assert.Equal(128d, openLifecycle.OpenedPacketCount);
        Assert.True(openLifecycle.HasReachedIntegrityLimit);
        Assert.Equal(QuicConnectionPhase.Discarded, runtime.Phase);
        Assert.Equal(QuicTransportErrorCode.AeadLimitReached, runtime.TerminalState?.Close.TransportErrorCode);
        Assert.Contains(result.Effects, effect => effect is QuicConnectionDiscardConnectionStateEffect);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionSendDatagramEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RuntimeOpenPathDiscardsBeforeUsingExhaustedRetainedOldKeys()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime();
        QuicRfc9001KeyUpdateRetentionTestSupport.ConfigureRuntime(runtime);
        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryInstallRuntimeOneRttKeyUpdate(runtime));

        QuicAeadKeyLifecycle retainedOldOpenLifecycle = runtime.TlsState.RetainedOldOneRttOpenKeyLifecycle!;
        Assert.NotNull(retainedOldOpenLifecycle);
        for (int packet = 0; packet < 128; packet++)
        {
            Assert.True(retainedOldOpenLifecycle.TryUseForOpening());
        }

        Assert.True(retainedOldOpenLifecycle.HasReachedIntegrityLimit);

        QuicHandshakeFlowCoordinator peerCoordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();
        Assert.True(peerCoordinator.TryBuildProtectedApplicationDataPacket(
            [0x00],
            runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial!.Value,
            keyPhase: false,
            out _,
            out byte[] protectedPacket));

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 129,
                QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                protectedPacket),
            nowTicks: 129);

        Assert.True(result.StateChanged);
        Assert.Equal(128d, retainedOldOpenLifecycle.OpenedPacketCount);
        Assert.Equal(QuicConnectionPhase.Discarded, runtime.Phase);
        Assert.Equal(QuicTransportErrorCode.AeadLimitReached, runtime.TerminalState?.Close.TransportErrorCode);
        Assert.Contains(result.Effects, effect => effect is QuicConnectionDiscardConnectionStateEffect);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionSendDatagramEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AeadLimitPolicyAllowsOnlyStatelessResetsAfterIntegrityLimitIsReached()
    {
        QuicAeadKeyLifecycle keyLifecycle = CreateActiveLifecycle(confidentialityLimit: 16, integrityLimit: 1);

        Assert.True(keyLifecycle.TryUseForOpening());

        QuicAeadLimitDecision decision = QuicAeadLimitPolicy.EvaluateReceivedPacketResponse(
            keyLifecycle,
            connectionStoppedForAeadLimit: false);

        Assert.Equal(QuicAeadLimitAction.SendOnlyStatelessReset, decision.Action);
        Assert.Equal(QuicTransportErrorCode.AeadLimitReached, decision.TransportErrorCode);
        Assert.True(decision.RequiresConnectionStop);
        Assert.True(decision.AllowsOnlyStatelessReset);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AeadLimitPolicyKeepsOrdinaryResponsesBeforeAeadStop()
    {
        QuicAeadKeyLifecycle keyLifecycle = CreateActiveLifecycle(confidentialityLimit: 4, integrityLimit: 4);

        Assert.True(keyLifecycle.TryUseForOpening());

        QuicAeadLimitDecision decision = QuicAeadLimitPolicy.EvaluateReceivedPacketResponse(
            keyLifecycle,
            connectionStoppedForAeadLimit: false);

        Assert.Equal(QuicAeadLimitAction.Continue, decision.Action);
        Assert.Null(decision.TransportErrorCode);
        Assert.False(decision.RequiresConnectionStop);
        Assert.False(decision.AllowsOnlyStatelessReset);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzStatelessResetOnlyPolicy_RandomizedIntegrityLimitsChooseStatelessResetOnly()
    {
        Random random = new(unchecked((int)0x9001_6605));

        for (int iteration = 0; iteration < 64; iteration++)
        {
            int integrityLimit = random.Next(1, 24);
            QuicAeadKeyLifecycle keyLifecycle = CreateActiveLifecycle(confidentialityLimit: 128, integrityLimit);

            for (int packet = 0; packet < integrityLimit; packet++)
            {
                Assert.True(keyLifecycle.TryUseForOpening());
            }

            QuicAeadLimitDecision decision = QuicAeadLimitPolicy.EvaluateReceivedPacketResponse(
                keyLifecycle,
                connectionStoppedForAeadLimit: false);

            Assert.Equal(QuicAeadLimitAction.SendOnlyStatelessReset, decision.Action);
            Assert.True(decision.AllowsOnlyStatelessReset);
            Assert.Equal((double)integrityLimit, keyLifecycle.OpenedPacketCount);
        }
    }

    private static QuicAeadKeyLifecycle CreateActiveLifecycle(int confidentialityLimit, int integrityLimit)
    {
        QuicAeadKeyLifecycle keyLifecycle = new(new QuicAeadUsageLimits(confidentialityLimit, integrityLimit));
        Assert.True(keyLifecycle.TryActivate());
        return keyLifecycle;
    }
}
