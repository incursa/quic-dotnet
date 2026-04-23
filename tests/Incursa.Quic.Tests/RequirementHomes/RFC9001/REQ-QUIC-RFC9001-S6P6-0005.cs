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
    public void EndpointPreservesStatelessResetOnlyEmissionAfterAeadLimitDiscard()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime();
        QuicRfc9001KeyUpdateRetentionTestSupport.ConfigureRuntime(runtime);
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity;
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0xC0);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));
        Assert.True(endpoint.TryRegisterStatelessResetToken(handle, 6605UL, token));

        QuicConnectionTransitionResult result = ExhaustCurrentOpenIntegrityLimit(runtime);
        QuicConnectionDiscardConnectionStateEffect discard = Assert.Single(
            result.Effects.OfType<QuicConnectionDiscardConnectionStateEffect>());

        Assert.True(endpoint.TryApplyEffect(handle, discard));

        QuicConnectionStatelessResetEmissionResult emission = endpoint.TryCreateStatelessResetDatagram(
            handle,
            6605UL,
            triggeringPacketLength: 100,
            hasLoopPreventionState: true);

        Assert.True(emission.Emitted);
        Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.Emitted, emission.Disposition);
        Assert.Equal(pathIdentity, emission.PathIdentity);
        Assert.Equal(99, emission.Datagram.Length);
        Assert.True(QuicStatelessReset.IsPotentialStatelessReset(emission.Datagram.Span));
        QuicStatelessResetRequirementTestData.AssertTailTokenMatches(emission.Datagram.Span, token);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionSendDatagramEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void EndpointDoesNotFabricateStatelessResetOnlyEmissionAfterAeadLimitDiscardWithoutToken()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime();
        QuicRfc9001KeyUpdateRetentionTestSupport.ConfigureRuntime(runtime);
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity));

        QuicConnectionTransitionResult result = ExhaustCurrentOpenIntegrityLimit(runtime);
        QuicConnectionDiscardConnectionStateEffect discard = Assert.Single(
            result.Effects.OfType<QuicConnectionDiscardConnectionStateEffect>());

        Assert.True(endpoint.TryApplyEffect(handle, discard));

        QuicConnectionStatelessResetEmissionResult emission = endpoint.TryCreateStatelessResetDatagram(
            handle,
            6605UL,
            triggeringPacketLength: 100,
            hasLoopPreventionState: true);

        Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.TokenUnavailable, emission.Disposition);
        Assert.False(emission.Emitted);
        Assert.True(emission.Datagram.IsEmpty);
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

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzEndpointStatelessResetOnlyEmissionAfterAeadLimitDiscard_RespectsLoopAndRateGates()
    {
        Random random = new(unchecked((int)0x9001_6655));

        for (int iteration = 0; iteration < 24; iteration++)
        {
            using QuicConnectionRuntimeEndpoint endpoint = new(2, maximumStatelessResetEmissionsPerRemoteAddress: 1);
            using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime();
            QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
            QuicConnectionPathIdentity pathIdentity = QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity;
            byte[] token = QuicStatelessResetRequirementTestData.CreateToken((byte)(0xD0 + iteration));
            bool hasLoopPreventionState = random.Next(0, 2) == 0;
            int triggeringPacketLength = QuicStatelessReset.MinimumDatagramLength + random.Next(0, 32);

            Assert.True(endpoint.TryRegisterConnection(handle, runtime));
            Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));
            Assert.True(endpoint.TryRegisterStatelessResetToken(handle, (ulong)(7000 + iteration), token));
            Assert.True(endpoint.TryApplyEffect(
                handle,
                new QuicConnectionDiscardConnectionStateEffect(CreateAeadLimitTerminalState(iteration))));

            QuicConnectionStatelessResetEmissionResult first = endpoint.TryCreateStatelessResetDatagram(
                handle,
                (ulong)(7000 + iteration),
                triggeringPacketLength,
                hasLoopPreventionState);

            if (triggeringPacketLength == QuicStatelessReset.MinimumDatagramLength && !hasLoopPreventionState)
            {
                Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.LoopOrAmplificationPrevented, first.Disposition);
                Assert.False(first.Emitted);
                continue;
            }

            Assert.True(first.Emitted);
            Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.Emitted, first.Disposition);
            Assert.Equal(pathIdentity, first.PathIdentity);
            QuicStatelessResetRequirementTestData.AssertTailTokenMatches(first.Datagram.Span, token);

            QuicConnectionStatelessResetEmissionResult second = endpoint.TryCreateStatelessResetDatagram(
                handle,
                (ulong)(7000 + iteration),
                triggeringPacketLength,
                hasLoopPreventionState);
            Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.RateLimited, second.Disposition);
            Assert.False(second.Emitted);
        }
    }

    private static QuicAeadKeyLifecycle CreateActiveLifecycle(int confidentialityLimit, int integrityLimit)
    {
        QuicAeadKeyLifecycle keyLifecycle = new(new QuicAeadUsageLimits(confidentialityLimit, integrityLimit));
        Assert.True(keyLifecycle.TryActivate());
        return keyLifecycle;
    }

    private static QuicConnectionTransitionResult ExhaustCurrentOpenIntegrityLimit(QuicConnectionRuntime runtime)
    {
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
        }

        Assert.Equal(128d, openLifecycle.OpenedPacketCount);
        Assert.True(openLifecycle.HasReachedIntegrityLimit);
        Assert.Equal(QuicConnectionPhase.Discarded, runtime.Phase);
        Assert.Equal(QuicTransportErrorCode.AeadLimitReached, runtime.TerminalState?.Close.TransportErrorCode);
        return result;
    }

    private static QuicConnectionTerminalState CreateAeadLimitTerminalState(int enteredAtTicks)
    {
        return new QuicConnectionTerminalState(
            QuicConnectionPhase.Discarded,
            QuicConnectionCloseOrigin.Local,
            new QuicConnectionCloseMetadata(
                QuicTransportErrorCode.AeadLimitReached,
                ApplicationErrorCode: null,
                TriggeringFrameType: null,
                ReasonPhrase: "The connection reached the AEAD limit."),
            enteredAtTicks);
    }
}
