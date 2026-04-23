using System.Reflection;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual trace slice">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S6P5-0002">When selecting receive keys across phases, a recovered packet number higher than any packet number from the current key phase MUST use the next packet protection keys.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9001-S6P5-0002")]
public sealed class REQ_QUIC_RFC9001_S6P5_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveClientRuntimeUsesNextKeysForHigherRecoveredPacketNumbers()
    {
        AssertRuntimeUsesNextKeysForHigherRecoveredPacketNumbers(
            QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveServerRuntimeUsesNextKeysForHigherRecoveredPacketNumbers()
    {
        AssertRuntimeUsesNextKeysForHigherRecoveredPacketNumbers(
            () => QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ActiveClientRuntimeDoesNotInstallNextKeysForALowerCurrentPhasePacketAfterRetainingNextKeys()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);

        QuicTlsPacketProtectionMaterial currentOpenMaterial =
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value;
        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryGetRuntimeSuccessorPhaseOnePacketProtectionMaterial(
            runtime,
            out QuicTlsPacketProtectionMaterial successorOpenMaterial,
            out _));

        QuicHandshakeFlowCoordinator peerCoordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();
        Assert.True(peerCoordinator.TryBuildProtectedApplicationDataPacket(
            QuicRfc9001KeyPhaseTestSupport.CreatePingPayload(),
            currentOpenMaterial,
            keyPhase: false,
            out ulong currentPacketNumber,
            out byte[] currentProtectedPacket));
        Assert.True(peerCoordinator.TryBuildProtectedApplicationDataPacket(
            QuicRfc9001KeyPhaseTestSupport.CreatePingPayload(),
            successorOpenMaterial,
            keyPhase: true,
            out ulong higherPacketNumber,
            out byte[] tamperedHigherProtectedPacket));

        tamperedHigherProtectedPacket[^1] ^= 0x80;

        QuicConnectionTransitionResult tamperedResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 1,
                QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                tamperedHigherProtectedPacket),
            nowTicks: 1);

        Assert.True(tamperedResult.StateChanged);
        Assert.False(runtime.TlsState.KeyUpdateInstalled);
        Assert.Equal(0U, runtime.TlsState.CurrentOneRttKeyPhase);
        Assert.True(successorOpenMaterial.Matches(
            runtime.TlsState.RetainedNextOneRttOpenPacketProtectionMaterial!.Value));
        Assert.True(higherPacketNumber > currentPacketNumber);
        AssertPacketRequiresCurrentKeys(currentProtectedPacket, currentOpenMaterial, successorOpenMaterial);

        _ = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20_000,
                QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                currentProtectedPacket),
            nowTicks: 20_000);

        Assert.True(TryBuildApplicationAckFrame(runtime, 20_000, out QuicAckFrame ackFrame));
        Assert.Equal(currentPacketNumber, ackFrame.LargestAcknowledged);
        Assert.Equal(0U, ackFrame.FirstAckRange);
        Assert.False(runtime.TlsState.KeyUpdateInstalled);
        Assert.Equal(0U, runtime.TlsState.CurrentOneRttKeyPhase);
        Assert.True(currentOpenMaterial.Matches(runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value));
        Assert.True(successorOpenMaterial.Matches(
            runtime.TlsState.RetainedNextOneRttOpenPacketProtectionMaterial!.Value));
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.Null(runtime.TerminalState);
        Assert.Null(runtime.TlsState.FatalAlertCode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveClientRuntimeUsesSecondSuccessorKeysForHigherRecoveredPacketNumbersAfterRepeatedPeerUpdate()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001RepeatedKeyUpdateTestSupport.PrepareRepeatedPeerUpdateEligibility(
            runtime,
            out QuicTlsPacketProtectionMaterial secondSuccessorOpenMaterial,
            out QuicTlsPacketProtectionMaterial secondSuccessorProtectMaterial);

        QuicTlsPacketProtectionMaterial currentPhaseOneMaterial =
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value;
        QuicHandshakeFlowCoordinator peerCoordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();
        SkipPacketNumbers(peerCoordinator, currentPhaseOneMaterial, keyPhase: true, count: 8);
        Assert.True(peerCoordinator.TryBuildProtectedApplicationDataPacket(
            QuicRfc9001KeyPhaseTestSupport.CreatePingPayload(),
            currentPhaseOneMaterial,
            keyPhase: true,
            out ulong currentPacketNumber,
            out byte[] currentProtectedPacket));
        Assert.True(peerCoordinator.TryBuildProtectedApplicationDataPacket(
            QuicRfc9001KeyPhaseTestSupport.CreatePingPayload(),
            secondSuccessorOpenMaterial,
            keyPhase: false,
            out ulong higherPacketNumber,
            out byte[] higherProtectedPacket));

        Assert.True(higherPacketNumber > currentPacketNumber);
        AssertPacketRequiresNextKeys(
            higherProtectedPacket,
            currentPhaseOneMaterial,
            secondSuccessorOpenMaterial,
            expectedNextKeyPhase: false);

        _ = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 30_000,
                QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                currentProtectedPacket),
            nowTicks: 30_000);
        _ = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 40_000,
                QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                higherProtectedPacket),
            nowTicks: 40_000);

        Assert.True(TryBuildApplicationAckFrame(runtime, 40_000, out QuicAckFrame ackFrame));
        Assert.Equal(higherPacketNumber, ackFrame.LargestAcknowledged);
        Assert.Equal(higherPacketNumber - currentPacketNumber, ackFrame.FirstAckRange);
        Assert.True(runtime.TlsState.KeyUpdateInstalled);
        Assert.Equal(2U, runtime.TlsState.CurrentOneRttKeyPhase);
        Assert.True(secondSuccessorOpenMaterial.Matches(runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value));
        Assert.True(secondSuccessorProtectMaterial.Matches(runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value));
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.Null(runtime.TerminalState);
        Assert.Null(runtime.TlsState.FatalAlertCode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzHigherRecoveredPackets_UseNextKeysAcrossRepresentativePayloadSizes()
    {
        Random random = new(unchecked((int)0x9001_6502));

        for (int iteration = 0; iteration < 32; iteration++)
        {
            using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
            QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);

            QuicTlsPacketProtectionMaterial currentOpenMaterial =
                runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value;
            Assert.True(QuicRfc9001KeyPhaseTestSupport.TryGetRuntimeSuccessorPhaseOnePacketProtectionMaterial(
                runtime,
                out QuicTlsPacketProtectionMaterial successorOpenMaterial,
                out QuicTlsPacketProtectionMaterial successorProtectMaterial));

            QuicHandshakeFlowCoordinator peerCoordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();
            Assert.True(peerCoordinator.TryBuildProtectedApplicationDataPacket(
                CreateAckElicitingPayload(random.Next(1, 96)),
                currentOpenMaterial,
                keyPhase: false,
                out ulong currentPacketNumber,
                out byte[] currentProtectedPacket));
            Assert.True(peerCoordinator.TryBuildProtectedApplicationDataPacket(
                CreateAckElicitingPayload(random.Next(1, 96)),
                successorOpenMaterial,
                keyPhase: true,
                out ulong higherPacketNumber,
                out byte[] higherProtectedPacket));

            _ = runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: iteration * 2 + 1,
                    QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                    currentProtectedPacket),
                nowTicks: iteration * 2 + 1);
            _ = runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: 20_000 + (iteration * 2),
                    QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                    higherProtectedPacket),
                nowTicks: 20_000 + (iteration * 2));

            Assert.True(higherPacketNumber > currentPacketNumber);
            Assert.True(TryBuildApplicationAckFrame(runtime, 20_000 + (iteration * 2), out QuicAckFrame ackFrame));
            Assert.Equal(higherPacketNumber, ackFrame.LargestAcknowledged);
            Assert.Equal(higherPacketNumber - currentPacketNumber, ackFrame.FirstAckRange);
            Assert.True(runtime.TlsState.KeyUpdateInstalled);
            Assert.Equal(1U, runtime.TlsState.CurrentOneRttKeyPhase);
            Assert.True(successorOpenMaterial.Matches(runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value));
            Assert.True(successorProtectMaterial.Matches(runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value));
            Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
            Assert.Null(runtime.TerminalState);
            Assert.Null(runtime.TlsState.FatalAlertCode);
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzRepeatedHigherRecoveredPackets_UseSecondSuccessorKeysAcrossRepresentativePayloadSizes()
    {
        Random random = new(unchecked((int)0x9001_6512));

        for (int iteration = 0; iteration < 32; iteration++)
        {
            using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
            QuicRfc9001RepeatedKeyUpdateTestSupport.PrepareRepeatedPeerUpdateEligibility(
                runtime,
                out QuicTlsPacketProtectionMaterial secondSuccessorOpenMaterial,
                out _);

            QuicTlsPacketProtectionMaterial currentPhaseOneMaterial =
                runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value;
            QuicHandshakeFlowCoordinator peerCoordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();
            SkipPacketNumbers(peerCoordinator, currentPhaseOneMaterial, keyPhase: true, count: 8);
            Assert.True(peerCoordinator.TryBuildProtectedApplicationDataPacket(
                CreateAckElicitingPayload(random.Next(1, 96)),
                currentPhaseOneMaterial,
                keyPhase: true,
                out ulong currentPacketNumber,
                out byte[] currentProtectedPacket));
            Assert.True(peerCoordinator.TryBuildProtectedApplicationDataPacket(
                CreateAckElicitingPayload(random.Next(1, 96)),
                secondSuccessorOpenMaterial,
                keyPhase: false,
                out ulong higherPacketNumber,
                out byte[] higherProtectedPacket));

            _ = runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: 30_000 + (iteration * 2),
                    QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                    currentProtectedPacket),
                nowTicks: 30_000 + (iteration * 2));
            _ = runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: 40_000 + (iteration * 2),
                    QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                    higherProtectedPacket),
                nowTicks: 40_000 + (iteration * 2));

            Assert.True(higherPacketNumber > currentPacketNumber);
            Assert.True(TryBuildApplicationAckFrame(runtime, 40_000 + (iteration * 2), out QuicAckFrame ackFrame));
            Assert.Equal(higherPacketNumber, ackFrame.LargestAcknowledged);
            Assert.Equal(higherPacketNumber - currentPacketNumber, ackFrame.FirstAckRange);
            Assert.True(runtime.TlsState.KeyUpdateInstalled);
            Assert.Equal(2U, runtime.TlsState.CurrentOneRttKeyPhase);
            Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
            Assert.Null(runtime.TerminalState);
            Assert.Null(runtime.TlsState.FatalAlertCode);
        }
    }

    private static void AssertRuntimeUsesNextKeysForHigherRecoveredPacketNumbers(
        Func<QuicConnectionRuntime> runtimeFactory)
    {
        using QuicConnectionRuntime runtime = runtimeFactory();
        QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);
        MarkServerHandshakeDoneAsAlreadySent(runtime);

        QuicTlsPacketProtectionMaterial currentOpenMaterial =
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value;
        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryGetRuntimeSuccessorPhaseOnePacketProtectionMaterial(
            runtime,
            out QuicTlsPacketProtectionMaterial successorOpenMaterial,
            out QuicTlsPacketProtectionMaterial successorProtectMaterial));

        QuicHandshakeFlowCoordinator peerCoordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();
        Assert.True(peerCoordinator.TryBuildProtectedApplicationDataPacket(
            QuicRfc9001KeyPhaseTestSupport.CreatePingPayload(),
            currentOpenMaterial,
            keyPhase: false,
            out ulong currentPacketNumber,
            out byte[] currentProtectedPacket));
        Assert.True(peerCoordinator.TryBuildProtectedApplicationDataPacket(
            QuicRfc9001KeyPhaseTestSupport.CreatePingPayload(),
            successorOpenMaterial,
            keyPhase: true,
            out ulong higherPacketNumber,
            out byte[] higherProtectedPacket));

        Assert.True(higherPacketNumber > currentPacketNumber);
        AssertPacketRequiresNextKeys(higherProtectedPacket, currentOpenMaterial, successorOpenMaterial);

        _ = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 1,
                QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                currentProtectedPacket),
            nowTicks: 1);
        _ = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20_000,
                QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                higherProtectedPacket),
            nowTicks: 20_000);

        Assert.True(TryBuildApplicationAckFrame(runtime, 20_000, out QuicAckFrame ackFrame));
        Assert.Equal(higherPacketNumber, ackFrame.LargestAcknowledged);
        Assert.Equal(higherPacketNumber - currentPacketNumber, ackFrame.FirstAckRange);
        Assert.True(runtime.TlsState.KeyUpdateInstalled);
        Assert.Equal(1U, runtime.TlsState.CurrentOneRttKeyPhase);
        Assert.True(successorOpenMaterial.Matches(runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value));
        Assert.True(successorProtectMaterial.Matches(runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value));
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.Null(runtime.TerminalState);
        Assert.Null(runtime.TlsState.FatalAlertCode);
    }

    private static void AssertPacketRequiresNextKeys(
        byte[] protectedPacket,
        QuicTlsPacketProtectionMaterial currentOpenMaterial,
        QuicTlsPacketProtectionMaterial successorOpenMaterial,
        bool expectedNextKeyPhase = true)
    {
        QuicHandshakeFlowCoordinator coordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();
        Assert.False(coordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            currentOpenMaterial,
            out _,
            out _,
            out _,
            out _));
        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            successorOpenMaterial,
            out _,
            out _,
            out _,
            out bool observedKeyPhase));
        Assert.Equal(expectedNextKeyPhase, observedKeyPhase);
    }

    private static void AssertPacketRequiresCurrentKeys(
        byte[] protectedPacket,
        QuicTlsPacketProtectionMaterial currentOpenMaterial,
        QuicTlsPacketProtectionMaterial successorOpenMaterial)
    {
        QuicHandshakeFlowCoordinator coordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();
        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            currentOpenMaterial,
            out _,
            out _,
            out _,
            out bool observedKeyPhase));
        Assert.False(observedKeyPhase);
        Assert.False(coordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            successorOpenMaterial,
            out _,
            out _,
            out _,
            out _));
    }

    private static bool TryBuildApplicationAckFrame(
        QuicConnectionRuntime runtime,
        long nowTicks,
        out QuicAckFrame ackFrame)
    {
        ackFrame = new QuicAckFrame();

        FieldInfo sendRuntimeField = typeof(QuicConnectionRuntime).GetField(
            "sendRuntime",
            BindingFlags.NonPublic | BindingFlags.Instance)!;
        QuicConnectionSendRuntime sendRuntime =
            (QuicConnectionSendRuntime)sendRuntimeField.GetValue(runtime)!;

        MethodInfo getElapsedMicrosMethod = typeof(QuicConnectionRuntime).GetMethod(
            "GetElapsedMicros",
            BindingFlags.NonPublic | BindingFlags.Instance)!;
        ulong nowMicros = (ulong)getElapsedMicrosMethod.Invoke(runtime, [nowTicks])!;

        return sendRuntime.FlowController.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros,
            out ackFrame);
    }

    private static byte[] CreateAckElicitingPayload(int payloadLength)
    {
        byte[] payload = new byte[payloadLength];
        Assert.True(QuicFrameCodec.TryFormatPingFrame(payload, out int bytesWritten));
        Assert.Equal(1, bytesWritten);
        return payload;
    }

    private static void SkipPacketNumbers(
        QuicHandshakeFlowCoordinator coordinator,
        QuicTlsPacketProtectionMaterial material,
        bool keyPhase,
        int count)
    {
        for (int i = 0; i < count; i++)
        {
            Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
                QuicRfc9001KeyPhaseTestSupport.CreatePingPayload(),
                material,
                keyPhase,
                out _,
                out _));
        }
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
