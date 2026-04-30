using System.Linq;
using System.Reflection;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual trace slice">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S6P2-0002">If a peer initiates a key update, the endpoint MUST update its send keys to the corresponding key phase before sending an acknowledgment for a packet that was received with updated keys.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9001-S6P2-0002")]
public sealed class REQ_QUIC_RFC9001_S6P2_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveClientRuntimeProtectsTheAckForAPeerUpdatedKeyPacketWithUpdatedSendKeys()
    {
        AssertRuntimeProtectsTheAckForAPeerUpdatedKeyPacketWithUpdatedSendKeys(
            QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveServerRuntimeProtectsTheAckForAPeerUpdatedKeyPacketWithUpdatedSendKeys()
    {
        AssertRuntimeProtectsTheAckForAPeerUpdatedKeyPacketWithUpdatedSendKeys(
            () => QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ActiveClientRuntimeDoesNotAcknowledgeATamperedPeerUpdatedKeyPacketWithOldSendKeys()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);
        QuicTlsPacketProtectionMaterial priorProtectMaterial =
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value;

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryGetRuntimeSuccessorPhaseOnePacketProtectionMaterial(
            runtime,
            out QuicTlsPacketProtectionMaterial successorOpenMaterial,
            out _));

        byte[] protectedPacket = BuildProtectedApplicationPacket(
            successorOpenMaterial,
            QuicRfc9001KeyPhaseTestSupport.CreatePingPayload());
        protectedPacket[^1] ^= 0x80;

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 1,
                QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                protectedPacket),
            nowTicks: 1);

        Assert.False(runtime.TlsState.KeyUpdateInstalled);
        Assert.True(priorProtectMaterial.Matches(runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value));
        Assert.DoesNotContain(result.Effects, static effect => effect is QuicConnectionSendDatagramEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveClientRuntimeProtectsTheAckForARepeatedPeerUpdatedKeyPacketWithPhaseTwoSendKeys()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001RepeatedKeyUpdateTestSupport.PrepareRepeatedPeerUpdateEligibility(
            runtime,
            out QuicTlsPacketProtectionMaterial secondSuccessorOpenMaterial,
            out QuicTlsPacketProtectionMaterial secondSuccessorProtectMaterial);

        QuicTlsPacketProtectionMaterial phaseOneProtectMaterial =
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value;

        QuicHandshakeFlowCoordinator peerCoordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();
        List<QuicConnectionSendDatagramEffect> sendEffects = [];
        for (int packetIndex = 0; packetIndex < 4; packetIndex++)
        {
            Assert.True(peerCoordinator.TryBuildProtectedApplicationDataPacket(
                QuicRfc9001KeyPhaseTestSupport.CreatePingPayload(),
                secondSuccessorOpenMaterial,
                keyPhase: false,
                out byte[] protectedPacket));

            QuicConnectionTransitionResult result = runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: 30_000 + packetIndex,
                    QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                    protectedPacket),
                nowTicks: 30_000 + packetIndex);

            sendEffects.AddRange(result.Effects.OfType<QuicConnectionSendDatagramEffect>());
        }

        QuicConnectionSendDatagramEffect[] updatedKeyAckEffects = sendEffects.Where(effect =>
            TryOpenAckDatagram(
                effect.Datagram.Span,
                secondSuccessorProtectMaterial,
                out bool observedKeyPhase,
                out QuicAckFrame ackFrame)
            && !observedKeyPhase
            && ackFrame.LargestAcknowledged <= 3UL)
            .ToArray();
        Assert.NotEmpty(updatedKeyAckEffects);

        Assert.DoesNotContain(sendEffects, effect =>
            TryOpenAckDatagram(
                effect.Datagram.Span,
                phaseOneProtectMaterial,
                out _,
                out _));

        Assert.True(runtime.TlsState.KeyUpdateInstalled);
        Assert.Equal(2UL, runtime.TlsState.CurrentOneRttKeyPhase);
        Assert.True(secondSuccessorProtectMaterial.Matches(runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveClientRuntimeProtectsTheAckForAPeerPhaseFourUpdatedPacketWithPhaseFourSendKeys()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001RepeatedKeyUpdateTestSupport.PreparePhaseThreeCurrentWithOldDiscardedAndAcknowledged(runtime);

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryGetRuntimeSuccessorPhaseOnePacketProtectionMaterial(
            runtime,
            out QuicTlsPacketProtectionMaterial phaseFourOpenMaterial,
            out QuicTlsPacketProtectionMaterial phaseFourProtectMaterial));
        QuicTlsPacketProtectionMaterial phaseThreeProtectMaterial =
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value;

        QuicHandshakeFlowCoordinator peerCoordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();
        List<QuicConnectionSendDatagramEffect> sendEffects = [];
        for (int packetIndex = 0; packetIndex < 4; packetIndex++)
        {
            Assert.True(peerCoordinator.TryBuildProtectedApplicationDataPacket(
                QuicRfc9001KeyPhaseTestSupport.CreatePingPayload(),
                phaseFourOpenMaterial,
                keyPhase: false,
                out byte[] protectedPacket));

            QuicConnectionTransitionResult result = runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: 70_000 + packetIndex,
                    QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                    protectedPacket),
                nowTicks: 70_000 + packetIndex);

            sendEffects.AddRange(result.Effects.OfType<QuicConnectionSendDatagramEffect>());
        }

        QuicConnectionSendDatagramEffect[] updatedKeyAckEffects = sendEffects.Where(effect =>
            TryOpenAckDatagram(
                effect.Datagram.Span,
                phaseFourProtectMaterial,
                out bool observedKeyPhase,
                out QuicAckFrame ackFrame)
            && !observedKeyPhase
            && ackFrame.LargestAcknowledged <= 3UL)
            .ToArray();
        Assert.NotEmpty(updatedKeyAckEffects);

        Assert.DoesNotContain(sendEffects, effect =>
            TryOpenAckDatagram(
                effect.Datagram.Span,
                phaseThreeProtectMaterial,
                out _,
                out _));

        Assert.True(runtime.TlsState.KeyUpdateInstalled);
        Assert.Equal(4UL, runtime.TlsState.CurrentOneRttKeyPhase);
        Assert.True(phaseFourProtectMaterial.Matches(runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveClientRuntimeProtectsTheAckForAPeerPhaseFiveUpdatedPacketWithPhaseFiveSendKeys()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001RepeatedKeyUpdateTestSupport.PreparePhaseFourCurrentWithOldDiscardedAndAcknowledged(runtime);

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryGetRuntimeSuccessorPhaseOnePacketProtectionMaterial(
            runtime,
            out QuicTlsPacketProtectionMaterial phaseFiveOpenMaterial,
            out QuicTlsPacketProtectionMaterial phaseFiveProtectMaterial));
        QuicTlsPacketProtectionMaterial phaseFourProtectMaterial =
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value;

        QuicHandshakeFlowCoordinator peerCoordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();
        List<QuicConnectionSendDatagramEffect> sendEffects = [];
        for (int packetIndex = 0; packetIndex < 4; packetIndex++)
        {
            Assert.True(peerCoordinator.TryBuildProtectedApplicationDataPacket(
                QuicRfc9001KeyPhaseTestSupport.CreatePingPayload(),
                phaseFiveOpenMaterial,
                keyPhase: true,
                out byte[] protectedPacket));

            QuicConnectionTransitionResult result = runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: 90_000 + packetIndex,
                    QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                    protectedPacket),
                nowTicks: 90_000 + packetIndex);

            sendEffects.AddRange(result.Effects.OfType<QuicConnectionSendDatagramEffect>());
        }

        QuicConnectionSendDatagramEffect[] updatedKeyAckEffects = sendEffects.Where(effect =>
            TryOpenAckDatagram(
                effect.Datagram.Span,
                phaseFiveProtectMaterial,
                out bool observedKeyPhase,
                out QuicAckFrame ackFrame)
            && observedKeyPhase
            && ackFrame.LargestAcknowledged <= 3UL)
            .ToArray();
        Assert.NotEmpty(updatedKeyAckEffects);

        Assert.DoesNotContain(sendEffects, effect =>
            TryOpenAckDatagram(
                effect.Datagram.Span,
                phaseFourProtectMaterial,
                out _,
                out _));

        Assert.True(runtime.TlsState.KeyUpdateInstalled);
        Assert.Equal(5UL, runtime.TlsState.CurrentOneRttKeyPhase);
        Assert.True(phaseFiveProtectMaterial.Matches(runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value));
    }

    private static void AssertRuntimeProtectsTheAckForAPeerUpdatedKeyPacketWithUpdatedSendKeys(
        Func<QuicConnectionRuntime> runtimeFactory)
    {
        using QuicConnectionRuntime runtime = runtimeFactory();
        QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);
        MarkServerHandshakeDoneAsAlreadySent(runtime);

        QuicTlsPacketProtectionMaterial priorProtectMaterial =
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value;

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryGetRuntimeSuccessorPhaseOnePacketProtectionMaterial(
            runtime,
            out QuicTlsPacketProtectionMaterial successorOpenMaterial,
            out QuicTlsPacketProtectionMaterial successorProtectMaterial));

        QuicHandshakeFlowCoordinator peerCoordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();
        List<QuicConnectionSendDatagramEffect> sendEffects = [];
        for (int packetIndex = 0; packetIndex < 4; packetIndex++)
        {
            byte[] protectedPacket = BuildProtectedApplicationPacket(
                peerCoordinator,
                successorOpenMaterial,
                QuicRfc9001KeyPhaseTestSupport.CreatePingPayload());

            QuicConnectionTransitionResult result = runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: packetIndex + 1,
                    QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                    protectedPacket),
                nowTicks: packetIndex + 1);

            sendEffects.AddRange(result.Effects.OfType<QuicConnectionSendDatagramEffect>());
        }

        QuicConnectionSendDatagramEffect[] updatedKeyAckEffects = sendEffects.Where(effect =>
            TryOpenAckDatagram(
                effect.Datagram.Span,
                successorProtectMaterial,
                out bool observedKeyPhase,
                out QuicAckFrame ackFrame)
            && observedKeyPhase
            && ackFrame.LargestAcknowledged >= 1UL)
            .ToArray();
        Assert.NotEmpty(updatedKeyAckEffects);
        QuicConnectionSendDatagramEffect ackEffect = updatedKeyAckEffects[0];

        Assert.DoesNotContain(sendEffects, effect =>
            TryOpenAckDatagram(
                effect.Datagram.Span,
                priorProtectMaterial,
                out _,
                out _));

        Assert.True(ackEffect.Datagram.Length > 0);
        Assert.True(runtime.TlsState.KeyUpdateInstalled);
        Assert.True(successorProtectMaterial.Matches(runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value));
    }

    private static byte[] BuildProtectedApplicationPacket(
        QuicHandshakeFlowCoordinator coordinator,
        QuicTlsPacketProtectionMaterial material,
        byte[] payload)
    {
        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            payload,
            material,
            keyPhase: true,
            out byte[] protectedPacket));

        return protectedPacket;
    }

    private static byte[] BuildProtectedApplicationPacket(
        QuicTlsPacketProtectionMaterial material,
        byte[] payload)
    {
        return BuildProtectedApplicationPacket(
            QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator(),
            material,
            payload);
    }

    private static bool TryOpenAckDatagram(
        ReadOnlySpan<byte> datagram,
        QuicTlsPacketProtectionMaterial material,
        out bool observedKeyPhase,
        out QuicAckFrame ackFrame)
    {
        observedKeyPhase = default;
        ackFrame = new QuicAckFrame();

        QuicHandshakeFlowCoordinator coordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();
        return coordinator.TryOpenProtectedApplicationDataPacket(
            datagram,
            material,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength,
            out observedKeyPhase)
            && QuicFrameCodec.TryParseAckFrame(
                openedPacket.AsSpan(payloadOffset, payloadLength),
                out ackFrame,
                out int ackBytesConsumed)
            && ackBytesConsumed > 0;
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
