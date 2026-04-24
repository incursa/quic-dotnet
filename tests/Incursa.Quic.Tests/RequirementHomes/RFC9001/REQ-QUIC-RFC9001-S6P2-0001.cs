namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual trace slice">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S6P2-0001">To process a packet that appears to signal a key update, an endpoint MUST use the next packet protection key and IV.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9001-S6P2-0001")]
public sealed class REQ_QUIC_RFC9001_S6P2_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveClientRuntimeOpensPeerInitiatedUpdatePacketsWithNextKeys()
    {
        AssertRuntimeOpensPeerInitiatedUpdatePacketsWithNextKeys(
            QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveServerRuntimeOpensPeerInitiatedUpdatePacketsWithNextKeys()
    {
        AssertRuntimeOpensPeerInitiatedUpdatePacketsWithNextKeys(
            () => QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ActiveClientRuntimeRejectsNextKeyPacketsThatDoNotSignalTheNextKeyPhase()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);

        QuicTlsPacketProtectionMaterial priorOpenMaterial =
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value;
        QuicTlsPacketProtectionMaterial priorProtectMaterial =
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value;

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryGetRuntimeSuccessorPhaseOnePacketProtectionMaterial(
            runtime,
            out QuicTlsPacketProtectionMaterial successorOpenMaterial,
            out _));

        byte[] protectedPacket = BuildProtectedApplicationPacket(
            successorOpenMaterial,
            keyPhase: false,
            payload: QuicRfc9001KeyPhaseTestSupport.CreatePingPayload());

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 1,
                QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                protectedPacket),
            nowTicks: 1);

        Assert.False(runtime.TlsState.KeyUpdateInstalled);
        Assert.Equal(0U, runtime.TlsState.CurrentOneRttKeyPhase);
        Assert.True(priorOpenMaterial.Matches(runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value));
        Assert.True(priorProtectMaterial.Matches(runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value));
        Assert.DoesNotContain(result.Effects, static effect => effect is QuicConnectionSendDatagramEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveClientRuntimeOpensRepeatedPeerInitiatedUpdatePacketsWithNextKeysAfterConfirmationAndOldKeyDiscard()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001RepeatedKeyUpdateTestSupport.PrepareRepeatedPeerUpdateEligibility(
            runtime,
            out QuicTlsPacketProtectionMaterial secondSuccessorOpenMaterial,
            out QuicTlsPacketProtectionMaterial secondSuccessorProtectMaterial);

        QuicConnectionTransitionResult result =
            QuicRfc9001RepeatedKeyUpdateTestSupport.ReceivePeerUpdatePacket(
                runtime,
                secondSuccessorOpenMaterial,
                keyPhase: false,
                observedAtTicks: 30_000,
                QuicRfc9001KeyPhaseTestSupport.CreatePingPayload());

        Assert.True(result.StateChanged);
        Assert.True(runtime.TlsState.KeyUpdateInstalled);
        Assert.Equal(2U, runtime.TlsState.CurrentOneRttKeyPhase);
        Assert.False(runtime.TlsState.CurrentOneRttKeyPhaseBit);
        Assert.True(secondSuccessorOpenMaterial.Matches(runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value));
        Assert.True(secondSuccessorProtectMaterial.Matches(runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value));
        Assert.NotNull(runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.Null(runtime.TerminalState);
        Assert.Null(runtime.TlsState.FatalAlertCode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveClientRuntimeOpensPeerInitiatedPhaseThreeUpdatePacketsAfterPhaseTwoConfirmationAndOldKeyDiscard()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        _ = QuicRfc9001RepeatedKeyUpdateTestSupport.PreparePhaseTwoCurrentWithOldDiscardedAndAcknowledged(runtime);

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryGetRuntimeSuccessorPhaseOnePacketProtectionMaterial(
            runtime,
            out QuicTlsPacketProtectionMaterial phaseThreeOpenMaterial,
            out QuicTlsPacketProtectionMaterial phaseThreeProtectMaterial));

        QuicConnectionTransitionResult result =
            QuicRfc9001RepeatedKeyUpdateTestSupport.ReceivePeerUpdatePacket(
                runtime,
                phaseThreeOpenMaterial,
                keyPhase: true,
                observedAtTicks: 50_000,
                QuicRfc9001KeyPhaseTestSupport.CreatePingPayload());

        Assert.True(result.StateChanged);
        Assert.True(runtime.TlsState.KeyUpdateInstalled);
        Assert.Equal(3U, runtime.TlsState.CurrentOneRttKeyPhase);
        Assert.True(runtime.TlsState.CurrentOneRttKeyPhaseBit);
        Assert.True(phaseThreeOpenMaterial.Matches(runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value));
        Assert.True(phaseThreeProtectMaterial.Matches(runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value));
        Assert.NotNull(runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.Null(runtime.TerminalState);
        Assert.Null(runtime.TlsState.FatalAlertCode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveClientRuntimeOpensPeerInitiatedPhaseFourUpdatePacketsAfterPhaseThreeConfirmationAndOldKeyDiscard()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        _ = QuicRfc9001RepeatedKeyUpdateTestSupport.PreparePhaseThreeCurrentWithOldDiscardedAndAcknowledged(runtime);

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryGetRuntimeSuccessorPhaseOnePacketProtectionMaterial(
            runtime,
            out QuicTlsPacketProtectionMaterial phaseFourOpenMaterial,
            out QuicTlsPacketProtectionMaterial phaseFourProtectMaterial));

        QuicConnectionTransitionResult result =
            QuicRfc9001RepeatedKeyUpdateTestSupport.ReceivePeerUpdatePacket(
                runtime,
                phaseFourOpenMaterial,
                keyPhase: false,
                observedAtTicks: 70_000,
                QuicRfc9001KeyPhaseTestSupport.CreatePingPayload());

        Assert.True(result.StateChanged);
        Assert.True(runtime.TlsState.KeyUpdateInstalled);
        Assert.Equal(4U, runtime.TlsState.CurrentOneRttKeyPhase);
        Assert.False(runtime.TlsState.CurrentOneRttKeyPhaseBit);
        Assert.True(phaseFourOpenMaterial.Matches(runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value));
        Assert.True(phaseFourProtectMaterial.Matches(runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value));
        Assert.NotNull(runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.Null(runtime.TerminalState);
        Assert.Null(runtime.TlsState.FatalAlertCode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ActiveClientRuntimeRejectsRepeatedPeerUpdatePacketsThatDoNotSignalTheNextKeyPhase()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001RepeatedKeyUpdateTestSupport.PrepareRepeatedPeerUpdateEligibility(
            runtime,
            out QuicTlsPacketProtectionMaterial secondSuccessorOpenMaterial,
            out _);

        QuicTlsPacketProtectionMaterial phaseOneOpenMaterial =
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value;

        QuicConnectionTransitionResult result =
            QuicRfc9001RepeatedKeyUpdateTestSupport.ReceivePeerUpdatePacket(
                runtime,
                secondSuccessorOpenMaterial,
                keyPhase: true,
                observedAtTicks: 30_000,
                QuicRfc9001KeyPhaseTestSupport.CreatePingPayload());

        Assert.True(secondSuccessorOpenMaterial.Matches(
            runtime.TlsState.RetainedNextOneRttOpenPacketProtectionMaterial!.Value));
        Assert.Equal(1U, runtime.TlsState.CurrentOneRttKeyPhase);
        Assert.True(phaseOneOpenMaterial.Matches(runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value));
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.Null(runtime.TerminalState);
        Assert.Null(runtime.TlsState.FatalAlertCode);
        Assert.DoesNotContain(result.Effects, static effect => effect is QuicConnectionSendDatagramEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzPeerInitiatedNextKeyPackets_RandomizedPayloadLengthsInstallOnlyWhenTheNextPhaseBitIsPresent()
    {
        Random random = new(unchecked((int)0x9001_6201));

        for (int iteration = 0; iteration < 32; iteration++)
        {
            using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
            QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);

            Assert.True(QuicRfc9001KeyPhaseTestSupport.TryGetRuntimeSuccessorPhaseOnePacketProtectionMaterial(
                runtime,
                out QuicTlsPacketProtectionMaterial successorOpenMaterial,
                out _));

            byte[] protectedPacket = BuildProtectedApplicationPacket(
                successorOpenMaterial,
                keyPhase: true,
                payload: CreateAckElicitingPayload(random.Next(1, 96)));

            QuicConnectionTransitionResult result = runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: iteration + 1,
                    QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                    protectedPacket),
                nowTicks: iteration + 1);

            Assert.True(result.StateChanged);
            Assert.True(runtime.TlsState.KeyUpdateInstalled);
            Assert.Equal(1U, runtime.TlsState.CurrentOneRttKeyPhase);
            Assert.True(successorOpenMaterial.Matches(runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value));
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzRepeatedPeerInitiatedNextKeyPackets_RandomizedPayloadLengthsInstallOnlyWhenTheNextPhaseBitIsPresent()
    {
        Random random = new(unchecked((int)0x9001_6211));

        for (int iteration = 0; iteration < 32; iteration++)
        {
            using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
            QuicRfc9001RepeatedKeyUpdateTestSupport.PrepareRepeatedPeerUpdateEligibility(
                runtime,
                out QuicTlsPacketProtectionMaterial secondSuccessorOpenMaterial,
                out _);

            QuicConnectionTransitionResult result =
                QuicRfc9001RepeatedKeyUpdateTestSupport.ReceivePeerUpdatePacket(
                    runtime,
                    secondSuccessorOpenMaterial,
                    keyPhase: false,
                    observedAtTicks: 30_000 + iteration,
                    CreateAckElicitingPayload(random.Next(1, 96)));

            Assert.True(result.StateChanged);
            Assert.True(runtime.TlsState.KeyUpdateInstalled);
            Assert.Equal(2U, runtime.TlsState.CurrentOneRttKeyPhase);
            Assert.True(secondSuccessorOpenMaterial.Matches(runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value));
            Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
            Assert.Null(runtime.TerminalState);
            Assert.Null(runtime.TlsState.FatalAlertCode);
        }
    }

    private static void AssertRuntimeOpensPeerInitiatedUpdatePacketsWithNextKeys(
        Func<QuicConnectionRuntime> runtimeFactory)
    {
        using QuicConnectionRuntime runtime = runtimeFactory();
        QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryGetRuntimeSuccessorPhaseOnePacketProtectionMaterial(
            runtime,
            out QuicTlsPacketProtectionMaterial successorOpenMaterial,
            out QuicTlsPacketProtectionMaterial successorProtectMaterial));

        byte[] protectedPacket = BuildProtectedApplicationPacket(
            successorOpenMaterial,
            keyPhase: true,
            payload: QuicRfc9001KeyPhaseTestSupport.CreatePingPayload());

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 1,
                QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                protectedPacket),
            nowTicks: 1);

        Assert.True(result.StateChanged);
        Assert.True(runtime.TlsState.KeyUpdateInstalled);
        Assert.Equal(1U, runtime.TlsState.CurrentOneRttKeyPhase);
        Assert.True(successorOpenMaterial.Matches(runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value));
        Assert.True(successorProtectMaterial.Matches(runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value));
        Assert.NotNull(runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial);
    }

    private static byte[] BuildProtectedApplicationPacket(
        QuicTlsPacketProtectionMaterial material,
        bool keyPhase,
        byte[] payload)
    {
        QuicHandshakeFlowCoordinator coordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();
        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            payload,
            material,
            keyPhase,
            out byte[] protectedPacket));

        return protectedPacket;
    }

    private static byte[] CreateAckElicitingPayload(int payloadLength)
    {
        byte[] payload = new byte[payloadLength];
        Assert.True(QuicFrameCodec.TryFormatPingFrame(payload, out int bytesWritten));
        Assert.Equal(1, bytesWritten);
        return payload;
    }
}
