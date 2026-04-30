using System.Reflection;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual trace slice">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S6P3-0001">Endpoints responding to an apparent key update MUST NOT generate a timing signal that reveals whether the Key Phase bit was invalid.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9001-S6P3-0001")]
public sealed class REQ_QUIC_RFC9001_S6P3_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveClientRuntimeStillInstallsAnAuthenticatedSuccessorPacketWithTheMatchingKeyPhaseBit()
    {
        AssertRuntimeStillInstallsAuthenticatedSuccessorPacketWithMatchingKeyPhaseBit(
            QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveServerRuntimeStillInstallsAnAuthenticatedSuccessorPacketWithTheMatchingKeyPhaseBit()
    {
        AssertRuntimeStillInstallsAuthenticatedSuccessorPacketWithMatchingKeyPhaseBit(
            () => QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ActiveClientRuntimeDropsCurrentKeyPacketsThatCarryTheNextKeyPhaseBitWithoutClosing()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);

        QuicTlsPacketProtectionMaterial currentOpenMaterial =
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value;
        byte[] protectedPacket = QuicRfc9001KeyPhaseTestSupport.BuildProtectedApplicationPacket(
            currentOpenMaterial,
            keyPhase: true,
            QuicRfc9001KeyPhaseTestSupport.CreatePingPayload());

        QuicConnectionTransitionResult result = ReceivePacket(runtime, protectedPacket, observedAtTicks: 1);

        AssertInvalidKeyPhaseDidNotSignal(runtime, result);
        Assert.False(runtime.TlsState.KeyUpdateInstalled);
        Assert.Equal(0UL, runtime.TlsState.CurrentOneRttKeyPhase);
        Assert.True(currentOpenMaterial.Matches(runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ActiveClientRuntimeDropsSuccessorKeyPacketsThatCarryTheOldKeyPhaseBitWithoutClosing()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);

        QuicTlsPacketProtectionMaterial currentOpenMaterial =
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value;
        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryGetRuntimeSuccessorPhaseOnePacketProtectionMaterial(
            runtime,
            out QuicTlsPacketProtectionMaterial successorOpenMaterial,
            out _));
        byte[] protectedPacket = QuicRfc9001KeyPhaseTestSupport.BuildProtectedApplicationPacket(
            successorOpenMaterial,
            keyPhase: false,
            QuicRfc9001KeyPhaseTestSupport.CreatePingPayload());

        QuicConnectionTransitionResult result = ReceivePacket(runtime, protectedPacket, observedAtTicks: 1);

        Assert.True(result.StateChanged);
        AssertInvalidKeyPhaseDidNotSignal(runtime, result);
        Assert.False(runtime.TlsState.KeyUpdateInstalled);
        Assert.Equal(0UL, runtime.TlsState.CurrentOneRttKeyPhase);
        Assert.True(currentOpenMaterial.Matches(runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value));
        Assert.True(successorOpenMaterial.Matches(
            runtime.TlsState.RetainedNextOneRttOpenPacketProtectionMaterial!.Value));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzInvalidKeyPhasePackets_RandomizedPayloadSizesDoNotCloseOrSendAResponse()
    {
        Random random = new(unchecked((int)0x9001_6301));

        for (int iteration = 0; iteration < 32; iteration++)
        {
            using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
            QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);

            QuicTlsPacketProtectionMaterial currentOpenMaterial =
                runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value;
            Assert.True(QuicRfc9001KeyPhaseTestSupport.TryGetRuntimeSuccessorPhaseOnePacketProtectionMaterial(
                runtime,
                out QuicTlsPacketProtectionMaterial successorOpenMaterial,
                out _));

            bool protectWithCurrentKeys = (iteration & 1) == 0;
            QuicTlsPacketProtectionMaterial material = protectWithCurrentKeys
                ? currentOpenMaterial
                : successorOpenMaterial;
            bool invalidKeyPhase = protectWithCurrentKeys;
            byte[] protectedPacket = QuicRfc9001KeyPhaseTestSupport.BuildProtectedApplicationPacket(
                material,
                invalidKeyPhase,
                CreateAckElicitingPayload(random.Next(1, 96)));

            QuicConnectionTransitionResult result = ReceivePacket(
                runtime,
                protectedPacket,
                observedAtTicks: iteration + 1);

            AssertInvalidKeyPhaseDidNotSignal(runtime, result);
            Assert.False(runtime.TlsState.KeyUpdateInstalled);
            Assert.Equal(0UL, runtime.TlsState.CurrentOneRttKeyPhase);
            Assert.True(currentOpenMaterial.Matches(runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value));
        }
    }

    private static void AssertRuntimeStillInstallsAuthenticatedSuccessorPacketWithMatchingKeyPhaseBit(
        Func<QuicConnectionRuntime> runtimeFactory)
    {
        using QuicConnectionRuntime runtime = runtimeFactory();
        QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);
        MarkServerHandshakeDoneAsAlreadySent(runtime);

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryGetRuntimeSuccessorPhaseOnePacketProtectionMaterial(
            runtime,
            out QuicTlsPacketProtectionMaterial successorOpenMaterial,
            out QuicTlsPacketProtectionMaterial successorProtectMaterial));
        byte[] protectedPacket = QuicRfc9001KeyPhaseTestSupport.BuildProtectedApplicationPacket(
            successorOpenMaterial,
            keyPhase: true,
            QuicRfc9001KeyPhaseTestSupport.CreatePingPayload());

        QuicConnectionTransitionResult result = ReceivePacket(runtime, protectedPacket, observedAtTicks: 1);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.Null(runtime.TerminalState);
        Assert.Null(runtime.TlsState.FatalAlertCode);
        Assert.True(runtime.TlsState.KeyUpdateInstalled);
        Assert.Equal(1UL, runtime.TlsState.CurrentOneRttKeyPhase);
        Assert.True(successorOpenMaterial.Matches(runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value));
        Assert.True(successorProtectMaterial.Matches(runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value));
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

    private static void AssertInvalidKeyPhaseDidNotSignal(
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
