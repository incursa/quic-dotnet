using System.Linq;
using System.Reflection;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual trace slice">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S6P4-0001">An endpoint MUST NOT send packets protected with old keys.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9001-S6P4-0001")]
public sealed class REQ_QUIC_RFC9001_S6P4_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveClientRuntimeSendsPeerUpdateAcksWithNewKeysOnly()
    {
        AssertRuntimeSendsPeerUpdateAcksWithNewKeysOnly(
            QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveServerRuntimeSendsPeerUpdateAcksWithNewKeysOnly()
    {
        AssertRuntimeSendsPeerUpdateAcksWithNewKeysOnly(
            () => QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ActiveClientRuntimeDoesNotSendOldKeyAckForTamperedPeerUpdate()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryGetRuntimeSuccessorPhaseOnePacketProtectionMaterial(
            runtime,
            out QuicTlsPacketProtectionMaterial successorOpenMaterial,
            out _));

        byte[] protectedPacket = BuildProtectedApplicationPacket(
            QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator(),
            successorOpenMaterial,
            QuicRfc9001KeyPhaseTestSupport.CreatePingPayload());
        protectedPacket[^1] ^= 0x80;

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 1,
                QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                protectedPacket),
            nowTicks: 1);

        Assert.DoesNotContain(result.Effects, static effect => effect is QuicConnectionSendDatagramEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzPeerUpdateAckSends_RandomizedPayloadsNeverOpenWithOldKeys()
    {
        Random random = new(unchecked((int)0x9001_6401));

        for (int iteration = 0; iteration < 16; iteration++)
        {
            using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
            QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);
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
                    CreateAckElicitingPayload(random.Next(1, 96)));

                QuicConnectionTransitionResult result = runtime.Transition(
                    new QuicConnectionPacketReceivedEvent(
                        ObservedAtTicks: (iteration * 10) + packetIndex + 1,
                        QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                        protectedPacket),
                    nowTicks: (iteration * 10) + packetIndex + 1);

                sendEffects.AddRange(result.Effects.OfType<QuicConnectionSendDatagramEffect>());
            }

            Assert.NotEmpty(sendEffects);
            Assert.DoesNotContain(sendEffects, effect =>
                TryOpenAckDatagram(effect.Datagram.Span, priorProtectMaterial, out _, out _));
            Assert.Contains(sendEffects, effect =>
                TryOpenAckDatagram(effect.Datagram.Span, successorProtectMaterial, out bool keyPhase, out _)
                && keyPhase);
        }
    }

    private static void AssertRuntimeSendsPeerUpdateAcksWithNewKeysOnly(
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

        Assert.NotEmpty(sendEffects);
        Assert.DoesNotContain(sendEffects, effect =>
            TryOpenAckDatagram(effect.Datagram.Span, priorProtectMaterial, out _, out _));
        Assert.Contains(sendEffects, effect =>
            TryOpenAckDatagram(effect.Datagram.Span, successorProtectMaterial, out bool keyPhase, out _)
            && keyPhase);
        Assert.True(runtime.TlsState.RetainedOldOneRttProtectPacketProtectionMaterial.HasValue);
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

    private static byte[] CreateAckElicitingPayload(int payloadLength)
    {
        byte[] payload = new byte[payloadLength];
        Assert.True(QuicFrameCodec.TryFormatPingFrame(payload, out int bytesWritten));
        Assert.Equal(1, bytesWritten);
        return payload;
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
