using System.Reflection;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual trace slice">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S6P2-0003">An endpoint MAY treat consecutive peer key updates that occur before confirmation of the prior update as a connection error of type KEY_UPDATE_ERROR.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9001-S6P2-0003")]
public sealed class REQ_QUIC_RFC9001_S6P2_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveClientRuntimeKeepsTheFirstPeerUpdatePathAvailable()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);

        QuicConnectionTransitionResult result = ReceiveFirstPeerUpdate(runtime, observedAtTicks: 1);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.Null(runtime.TerminalState);
        Assert.Null(runtime.TlsState.FatalAlertCode);
        Assert.True(runtime.TlsState.KeyUpdateInstalled);
        Assert.Equal(1U, runtime.TlsState.CurrentOneRttKeyPhase);
        Assert.False(runtime.TlsState.CurrentOneRttKeyPhaseAcknowledged);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ActiveRuntimeDropsApparentConsecutivePeerUpdateBeforeConfirmationWithoutClosing(bool serverRuntime)
    {
        using QuicConnectionRuntime runtime = CreateFinishedRuntime(serverRuntime);
        QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);
        MarkServerHandshakeDoneAsAlreadySent(runtime);
        _ = ReceiveFirstPeerUpdate(runtime, observedAtTicks: 1);
        Assert.False(runtime.TlsState.CurrentOneRttKeyPhaseAcknowledged);

        QuicTlsPacketProtectionMaterial currentPhaseOneMaterial =
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value;
        byte[] protectedPacket = QuicRfc9001KeyPhaseTestSupport.BuildProtectedApplicationPacket(
            currentPhaseOneMaterial,
            keyPhase: false,
            QuicRfc9001KeyPhaseTestSupport.CreatePingPayload());

        QuicConnectionTransitionResult result = ReceivePacket(runtime, protectedPacket, observedAtTicks: 2);

        AssertApparentConsecutiveUpdateDidNotSignal(runtime, result);
        Assert.True(runtime.TlsState.KeyUpdateInstalled);
        Assert.Equal(1U, runtime.TlsState.CurrentOneRttKeyPhase);
        Assert.False(runtime.TlsState.CurrentOneRttKeyPhaseAcknowledged);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ActiveClientRuntimeDropsSecondSuccessorPeerUpdateBeforeCurrentPhaseConfirmationWithoutClosing()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);
        _ = ReceiveFirstPeerUpdate(runtime, observedAtTicks: 1);
        Assert.False(runtime.TlsState.CurrentOneRttKeyPhaseAcknowledged);

        QuicTlsPacketProtectionMaterial currentPhaseOneMaterial =
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value;
        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryGetRuntimeSuccessorPhaseOnePacketProtectionMaterial(
            runtime,
            out QuicTlsPacketProtectionMaterial secondSuccessorOpenMaterial,
            out _));

        byte[] protectedPacket = QuicRfc9001KeyPhaseTestSupport.BuildProtectedApplicationPacket(
            secondSuccessorOpenMaterial,
            keyPhase: false,
            QuicRfc9001KeyPhaseTestSupport.CreatePingPayload());

        QuicConnectionTransitionResult result = ReceivePacket(runtime, protectedPacket, observedAtTicks: 2);

        AssertApparentConsecutiveUpdateDidNotSignal(runtime, result);
        Assert.True(runtime.TlsState.KeyUpdateInstalled);
        Assert.Equal(1U, runtime.TlsState.CurrentOneRttKeyPhase);
        Assert.False(runtime.TlsState.CurrentOneRttKeyPhaseAcknowledged);
        Assert.False(runtime.TlsState.RetainedNextOneRttOpenPacketProtectionMaterial.HasValue);
        Assert.True(currentPhaseOneMaterial.Matches(runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzApparentConsecutivePeerUpdatesBeforeConfirmation_RandomizedPayloadSizesDoNotClose()
    {
        Random random = new(unchecked((int)0x9001_6203));

        for (int iteration = 0; iteration < 32; iteration++)
        {
            using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
            QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);
            _ = ReceiveFirstPeerUpdate(runtime, observedAtTicks: iteration + 1);

            QuicTlsPacketProtectionMaterial currentPhaseOneMaterial =
                runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value;
            byte[] protectedPacket = QuicRfc9001KeyPhaseTestSupport.BuildProtectedApplicationPacket(
                currentPhaseOneMaterial,
                keyPhase: false,
                CreateAckElicitingPayload(random.Next(1, 96)));

            QuicConnectionTransitionResult result = ReceivePacket(
                runtime,
                protectedPacket,
                observedAtTicks: iteration + 100);

            AssertApparentConsecutiveUpdateDidNotSignal(runtime, result);
            Assert.True(runtime.TlsState.KeyUpdateInstalled);
            Assert.Equal(1U, runtime.TlsState.CurrentOneRttKeyPhase);
            Assert.False(runtime.TlsState.CurrentOneRttKeyPhaseAcknowledged);
        }
    }

    private static QuicConnectionRuntime CreateFinishedRuntime(bool serverRuntime)
    {
        return serverRuntime
            ? QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime()
            : QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
    }

    private static QuicConnectionTransitionResult ReceiveFirstPeerUpdate(
        QuicConnectionRuntime runtime,
        long observedAtTicks)
    {
        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryGetRuntimeSuccessorPhaseOnePacketProtectionMaterial(
            runtime,
            out QuicTlsPacketProtectionMaterial successorOpenMaterial,
            out _));

        byte[] protectedPacket = QuicRfc9001KeyPhaseTestSupport.BuildProtectedApplicationPacket(
            successorOpenMaterial,
            keyPhase: true,
            QuicRfc9001KeyPhaseTestSupport.CreatePingPayload());

        return ReceivePacket(runtime, protectedPacket, observedAtTicks);
    }

    private static QuicConnectionTransitionResult ReceivePacket(
        QuicConnectionRuntime runtime,
        byte[] protectedPacket,
        long observedAtTicks)
    {
        return runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: observedAtTicks,
                QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                protectedPacket),
            nowTicks: observedAtTicks);
    }

    private static void AssertApparentConsecutiveUpdateDidNotSignal(
        QuicConnectionRuntime runtime,
        QuicConnectionTransitionResult result)
    {
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.Null(runtime.TerminalState);
        Assert.Null(runtime.TlsState.FatalAlertCode);
        Assert.DoesNotContain(result.Effects, static effect => effect is QuicConnectionSendDatagramEffect);
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
