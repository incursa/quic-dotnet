using System.Linq;
using System.Reflection;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual trace slice">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S6P4-0003">If an endpoint successfully removes protection with old keys after newer keys were used for lower packet numbers, it MUST treat that condition as a connection error of type KEY_UPDATE_ERROR.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9001-S6P4-0003")]
public sealed class REQ_QUIC_RFC9001_S6P4_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveClientRuntimeRejectsOldKeyPacketsThatViolatePacketNumberOrdering()
    {
        AssertRuntimeRejectsOldKeyPacketsThatViolatePacketNumberOrdering(
            QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveServerRuntimeRejectsOldKeyPacketsThatViolatePacketNumberOrdering()
    {
        AssertRuntimeRejectsOldKeyPacketsThatViolatePacketNumberOrdering(
            () => QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ActiveClientRuntimeDoesNotRaiseKeyUpdateErrorForALowerRecoveredOldKeyPacket()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryInstallRuntimeOneRttKeyUpdate(runtime));

        QuicTlsPacketProtectionMaterial retainedOldOpenMaterial =
            runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial!.Value;
        QuicTlsPacketProtectionMaterial currentOpenMaterial =
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value;

        QuicHandshakeFlowCoordinator peerCoordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();
        Assert.True(peerCoordinator.TryBuildProtectedApplicationDataPacket(
            QuicRfc9001KeyPhaseTestSupport.CreatePingPayload(),
            retainedOldOpenMaterial,
            keyPhase: false,
            out ulong oldPacketNumber,
            out byte[] oldProtectedPacket));
        Assert.True(peerCoordinator.TryBuildProtectedApplicationDataPacket(
            QuicRfc9001KeyPhaseTestSupport.CreatePingPayload(),
            currentOpenMaterial,
            keyPhase: true,
            out ulong currentPacketNumber,
            out byte[] currentProtectedPacket));

        Assert.True(currentPacketNumber > oldPacketNumber);

        _ = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 1,
                QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                currentProtectedPacket),
            nowTicks: 1);
        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 2,
                QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                oldProtectedPacket),
            nowTicks: 2);

        Assert.False(result.Effects.OfType<QuicConnectionNotifyStreamsOfTerminalStateEffect>().Any());
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.Null(runtime.TerminalState);
        Assert.Null(runtime.TlsState.FatalAlertCode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzOldKeyPacketOrderingViolations_RaiseKeyUpdateErrorAcrossRepresentativePayloadSizes()
    {
        Random random = new(unchecked((int)0x9001_6403));

        for (int iteration = 0; iteration < 32; iteration++)
        {
            using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
            QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);

            Assert.True(QuicRfc9001KeyPhaseTestSupport.TryInstallRuntimeOneRttKeyUpdate(runtime));

            QuicTlsPacketProtectionMaterial retainedOldOpenMaterial =
                runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial!.Value;
            QuicTlsPacketProtectionMaterial currentOpenMaterial =
                runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value;

            QuicHandshakeFlowCoordinator peerCoordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();
            Assert.True(peerCoordinator.TryBuildProtectedApplicationDataPacket(
                CreateAckElicitingPayload(random.Next(1, 96)),
                currentOpenMaterial,
                keyPhase: true,
                out ulong currentPacketNumber,
                out byte[] currentProtectedPacket));
            Assert.True(peerCoordinator.TryBuildProtectedApplicationDataPacket(
                CreateAckElicitingPayload(random.Next(1, 96)),
                retainedOldOpenMaterial,
                keyPhase: false,
                out ulong oldPacketNumber,
                out byte[] oldProtectedPacket));

            _ = runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: iteration * 2 + 1,
                    QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                    currentProtectedPacket),
                nowTicks: iteration * 2 + 1);
            QuicConnectionTransitionResult result = runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: iteration * 2 + 2,
                    QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                    oldProtectedPacket),
                nowTicks: iteration * 2 + 2);

            Assert.True(oldPacketNumber > currentPacketNumber);
            Assert.True(result.StateChanged);
            Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
            Assert.Equal(QuicTransportErrorCode.KeyUpdateError, runtime.TerminalState?.Close.TransportErrorCode);
            Assert.Equal(
                "The peer sent an old-key packet that violated packet-number ordering.",
                runtime.TerminalState?.Close.ReasonPhrase);
        }
    }

    private static void AssertRuntimeRejectsOldKeyPacketsThatViolatePacketNumberOrdering(
        Func<QuicConnectionRuntime> runtimeFactory)
    {
        using QuicConnectionRuntime runtime = runtimeFactory();
        QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);
        MarkServerHandshakeDoneAsAlreadySent(runtime);

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryInstallRuntimeOneRttKeyUpdate(runtime));

        QuicTlsPacketProtectionMaterial retainedOldOpenMaterial =
            runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial!.Value;
        QuicTlsPacketProtectionMaterial currentOpenMaterial =
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value;

        QuicHandshakeFlowCoordinator peerCoordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();
        Assert.True(peerCoordinator.TryBuildProtectedApplicationDataPacket(
            QuicRfc9001KeyPhaseTestSupport.CreatePingPayload(),
            currentOpenMaterial,
            keyPhase: true,
            out ulong currentPacketNumber,
            out byte[] currentProtectedPacket));
        Assert.True(peerCoordinator.TryBuildProtectedApplicationDataPacket(
            QuicRfc9001KeyPhaseTestSupport.CreatePingPayload(),
            retainedOldOpenMaterial,
            keyPhase: false,
            out ulong oldPacketNumber,
            out byte[] oldProtectedPacket));

        Assert.True(oldPacketNumber > currentPacketNumber);

        _ = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 1,
                QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                currentProtectedPacket),
            nowTicks: 1);
        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 2,
                QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                oldProtectedPacket),
            nowTicks: 2);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.Equal(QuicConnectionCloseOrigin.Local, runtime.TerminalState?.Origin);
        Assert.Equal(QuicTransportErrorCode.KeyUpdateError, runtime.TerminalState?.Close.TransportErrorCode);
        Assert.Equal(
            "The peer sent an old-key packet that violated packet-number ordering.",
            runtime.TerminalState?.Close.ReasonPhrase);
        Assert.Contains(result.Effects, static effect => effect is QuicConnectionNotifyStreamsOfTerminalStateEffect);
        Assert.Contains(result.Effects, static effect => effect is QuicConnectionSendDatagramEffect);
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
