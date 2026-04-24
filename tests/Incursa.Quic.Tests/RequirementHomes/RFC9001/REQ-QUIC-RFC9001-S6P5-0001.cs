using System.Reflection;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual trace slice">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S6P5-0001">When selecting receive keys across phases, a recovered packet number lower than any packet number from the current key phase MUST use the previous packet protection keys.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9001-S6P5-0001")]
public sealed class REQ_QUIC_RFC9001_S6P5_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveClientRuntimeUsesPreviousKeysForLowerRecoveredPacketNumbers()
    {
        AssertRuntimeUsesPreviousKeysForLowerRecoveredPacketNumbers(
            QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveServerRuntimeUsesPreviousKeysForLowerRecoveredPacketNumbers()
    {
        AssertRuntimeUsesPreviousKeysForLowerRecoveredPacketNumbers(
            () => QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveClientRuntimeUsesPreviousPhaseOneKeysForLowerRecoveredPacketNumbersAfterRepeatedLocalUpdate()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        InstallRepeatedLocalUpdate(runtime);

        QuicTlsPacketProtectionMaterial retainedPhaseOneOpenMaterial =
            runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial!.Value;
        QuicTlsPacketProtectionMaterial phaseTwoOpenMaterial =
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value;

        QuicHandshakeFlowCoordinator peerCoordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();
        SkipPacketNumbers(peerCoordinator, phaseTwoOpenMaterial, keyPhase: false, count: 8);
        Assert.True(peerCoordinator.TryBuildProtectedApplicationDataPacket(
            QuicRfc9001KeyPhaseTestSupport.CreatePingPayload(),
            retainedPhaseOneOpenMaterial,
            keyPhase: true,
            out ulong oldPacketNumber,
            out byte[] oldProtectedPacket));
        Assert.True(peerCoordinator.TryBuildProtectedApplicationDataPacket(
            QuicRfc9001KeyPhaseTestSupport.CreatePingPayload(),
            phaseTwoOpenMaterial,
            keyPhase: false,
            out ulong currentPacketNumber,
            out byte[] currentProtectedPacket));

        Assert.True(currentPacketNumber > oldPacketNumber);
        AssertPacketRequiresOldKeys(
            oldProtectedPacket,
            phaseTwoOpenMaterial,
            retainedPhaseOneOpenMaterial,
            expectedRetainedOldKeyPhase: true);

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
                oldProtectedPacket),
            nowTicks: 40_000);

        Assert.True(TryBuildApplicationAckFrame(runtime, 40_000, out QuicAckFrame ackFrame));
        Assert.Equal(currentPacketNumber, ackFrame.LargestAcknowledged);
        Assert.Equal(currentPacketNumber - oldPacketNumber, ackFrame.FirstAckRange);
        Assert.Equal(2U, runtime.TlsState.CurrentOneRttKeyPhase);
        Assert.Equal(1U, runtime.TlsState.RetainedOldOneRttPacketProtectionKeyPhase);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.Null(runtime.TerminalState);
        Assert.Null(runtime.TlsState.FatalAlertCode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveClientRuntimeUsesPreviousPhaseTwoKeysForLowerRecoveredPacketNumbersAfterPhaseThreeUpdate()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001RepeatedKeyUpdateTestSupport.PrepareLocalPhaseThreeWithPhaseTwoRetained(runtime);

        QuicTlsPacketProtectionMaterial retainedPhaseTwoOpenMaterial =
            runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial!.Value;
        QuicTlsPacketProtectionMaterial phaseThreeOpenMaterial =
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value;

        QuicHandshakeFlowCoordinator peerCoordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();
        SkipPacketNumbers(peerCoordinator, phaseThreeOpenMaterial, keyPhase: true, count: 8);
        Assert.True(peerCoordinator.TryBuildProtectedApplicationDataPacket(
            QuicRfc9001KeyPhaseTestSupport.CreatePingPayload(),
            retainedPhaseTwoOpenMaterial,
            keyPhase: false,
            out ulong oldPacketNumber,
            out byte[] oldProtectedPacket));
        Assert.True(peerCoordinator.TryBuildProtectedApplicationDataPacket(
            QuicRfc9001KeyPhaseTestSupport.CreatePingPayload(),
            phaseThreeOpenMaterial,
            keyPhase: true,
            out ulong currentPacketNumber,
            out byte[] currentProtectedPacket));

        Assert.True(currentPacketNumber > oldPacketNumber);
        AssertPacketRequiresOldKeys(
            oldProtectedPacket,
            phaseThreeOpenMaterial,
            retainedPhaseTwoOpenMaterial,
            expectedRetainedOldKeyPhase: false);

        _ = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 50_000,
                QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                currentProtectedPacket),
            nowTicks: 50_000);
        _ = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 60_000,
                QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                oldProtectedPacket),
            nowTicks: 60_000);

        Assert.True(TryBuildApplicationAckFrame(runtime, 60_000, out QuicAckFrame ackFrame));
        Assert.Equal(currentPacketNumber, ackFrame.LargestAcknowledged);
        Assert.Equal(currentPacketNumber - oldPacketNumber, ackFrame.FirstAckRange);
        Assert.Equal(3U, runtime.TlsState.CurrentOneRttKeyPhase);
        Assert.Equal(2U, runtime.TlsState.RetainedOldOneRttPacketProtectionKeyPhase);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.Null(runtime.TerminalState);
        Assert.Null(runtime.TlsState.FatalAlertCode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveClientRuntimeUsesPreviousPhaseThreeKeysForLowerRecoveredPacketNumbersAfterPhaseFourUpdate()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001RepeatedKeyUpdateTestSupport.PrepareLocalPhaseFourWithPhaseThreeRetained(runtime);

        QuicTlsPacketProtectionMaterial retainedPhaseThreeOpenMaterial =
            runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial!.Value;
        QuicTlsPacketProtectionMaterial phaseFourOpenMaterial =
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value;

        QuicHandshakeFlowCoordinator peerCoordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();
        SkipPacketNumbers(peerCoordinator, phaseFourOpenMaterial, keyPhase: false, count: 8);
        Assert.True(peerCoordinator.TryBuildProtectedApplicationDataPacket(
            QuicRfc9001KeyPhaseTestSupport.CreatePingPayload(),
            retainedPhaseThreeOpenMaterial,
            keyPhase: true,
            out ulong oldPacketNumber,
            out byte[] oldProtectedPacket));
        Assert.True(peerCoordinator.TryBuildProtectedApplicationDataPacket(
            QuicRfc9001KeyPhaseTestSupport.CreatePingPayload(),
            phaseFourOpenMaterial,
            keyPhase: false,
            out ulong currentPacketNumber,
            out byte[] currentProtectedPacket));

        Assert.True(currentPacketNumber > oldPacketNumber);
        AssertPacketRequiresOldKeys(
            oldProtectedPacket,
            phaseFourOpenMaterial,
            retainedPhaseThreeOpenMaterial,
            expectedRetainedOldKeyPhase: true);

        _ = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 70_000,
                QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                currentProtectedPacket),
            nowTicks: 70_000);
        _ = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 80_000,
                QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                oldProtectedPacket),
            nowTicks: 80_000);

        Assert.True(TryBuildApplicationAckFrame(runtime, 80_000, out QuicAckFrame ackFrame));
        Assert.Equal(currentPacketNumber, ackFrame.LargestAcknowledged);
        Assert.Equal(currentPacketNumber - oldPacketNumber, ackFrame.FirstAckRange);
        Assert.Equal(4U, runtime.TlsState.CurrentOneRttKeyPhase);
        Assert.Equal(3U, runtime.TlsState.RetainedOldOneRttPacketProtectionKeyPhase);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.Null(runtime.TerminalState);
        Assert.Null(runtime.TlsState.FatalAlertCode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ActiveClientRuntimeRejectsPreviousPhaseOnePacketsWithThePhaseZeroBitAfterRepeatedLocalUpdate()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        InstallRepeatedLocalUpdate(runtime);

        QuicTlsPacketProtectionMaterial retainedPhaseOneOpenMaterial =
            runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial!.Value;
        QuicTlsPacketProtectionMaterial phaseTwoOpenMaterial =
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value;

        QuicHandshakeFlowCoordinator peerCoordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();
        SkipPacketNumbers(peerCoordinator, phaseTwoOpenMaterial, keyPhase: false, count: 8);
        Assert.True(peerCoordinator.TryBuildProtectedApplicationDataPacket(
            QuicRfc9001KeyPhaseTestSupport.CreatePingPayload(),
            retainedPhaseOneOpenMaterial,
            keyPhase: false,
            out ulong oldPacketNumber,
            out byte[] oldProtectedPacket));
        Assert.True(peerCoordinator.TryBuildProtectedApplicationDataPacket(
            QuicRfc9001KeyPhaseTestSupport.CreatePingPayload(),
            phaseTwoOpenMaterial,
            keyPhase: false,
            out ulong currentPacketNumber,
            out byte[] currentProtectedPacket));

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
                oldProtectedPacket),
            nowTicks: 40_000);

        Assert.True(TryBuildApplicationAckFrame(runtime, 40_000, out QuicAckFrame ackFrame));
        Assert.True(currentPacketNumber > oldPacketNumber);
        Assert.Equal(currentPacketNumber, ackFrame.LargestAcknowledged);
        Assert.Equal(0UL, ackFrame.FirstAckRange);
        Assert.Equal(2U, runtime.TlsState.CurrentOneRttKeyPhase);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.Null(runtime.TerminalState);
        Assert.Null(runtime.TlsState.FatalAlertCode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzLowerRecoveredPackets_UsePreviousKeysAcrossRepresentativePayloadSizes()
    {
        Random random = new(unchecked((int)0x9001_6501));

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
                retainedOldOpenMaterial,
                keyPhase: false,
                out ulong oldPacketNumber,
                out byte[] oldProtectedPacket));
            Assert.True(peerCoordinator.TryBuildProtectedApplicationDataPacket(
                CreateAckElicitingPayload(random.Next(1, 96)),
                currentOpenMaterial,
                keyPhase: true,
                out ulong currentPacketNumber,
                out byte[] currentProtectedPacket));

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
                    oldProtectedPacket),
                nowTicks: 20_000 + (iteration * 2));

            Assert.True(currentPacketNumber > oldPacketNumber);
            Assert.True(TryBuildApplicationAckFrame(runtime, 20_000 + (iteration * 2), out QuicAckFrame ackFrame));
            Assert.Equal(currentPacketNumber, ackFrame.LargestAcknowledged);
            Assert.Equal(currentPacketNumber - oldPacketNumber, ackFrame.FirstAckRange);
            Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
            Assert.Null(runtime.TerminalState);
            Assert.Null(runtime.TlsState.FatalAlertCode);
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzRepeatedLowerRecoveredPackets_UsePreviousPhaseOneKeysAcrossRepresentativePayloadSizes()
    {
        Random random = new(unchecked((int)0x9001_6511));

        for (int iteration = 0; iteration < 32; iteration++)
        {
            using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
            InstallRepeatedLocalUpdate(runtime);

            QuicTlsPacketProtectionMaterial retainedPhaseOneOpenMaterial =
                runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial!.Value;
            QuicTlsPacketProtectionMaterial phaseTwoOpenMaterial =
                runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value;

            QuicHandshakeFlowCoordinator peerCoordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();
            SkipPacketNumbers(peerCoordinator, phaseTwoOpenMaterial, keyPhase: false, count: 8);
            Assert.True(peerCoordinator.TryBuildProtectedApplicationDataPacket(
                CreateAckElicitingPayload(random.Next(1, 96)),
                retainedPhaseOneOpenMaterial,
                keyPhase: true,
                out ulong oldPacketNumber,
                out byte[] oldProtectedPacket));
            Assert.True(peerCoordinator.TryBuildProtectedApplicationDataPacket(
                CreateAckElicitingPayload(random.Next(1, 96)),
                phaseTwoOpenMaterial,
                keyPhase: false,
                out ulong currentPacketNumber,
                out byte[] currentProtectedPacket));

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
                    oldProtectedPacket),
                nowTicks: 40_000 + (iteration * 2));

            Assert.True(currentPacketNumber > oldPacketNumber);
            Assert.True(TryBuildApplicationAckFrame(runtime, 40_000 + (iteration * 2), out QuicAckFrame ackFrame));
            Assert.Equal(currentPacketNumber, ackFrame.LargestAcknowledged);
            Assert.Equal(currentPacketNumber - oldPacketNumber, ackFrame.FirstAckRange);
            Assert.Equal(2U, runtime.TlsState.CurrentOneRttKeyPhase);
            Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
            Assert.Null(runtime.TerminalState);
            Assert.Null(runtime.TlsState.FatalAlertCode);
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzPhaseThreeLowerRecoveredPackets_UsePreviousPhaseTwoKeysAcrossRepresentativePayloadSizes()
    {
        Random random = new(unchecked((int)0x9001_6513));

        for (int iteration = 0; iteration < 32; iteration++)
        {
            using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
            QuicRfc9001RepeatedKeyUpdateTestSupport.PrepareLocalPhaseThreeWithPhaseTwoRetained(runtime);

            QuicTlsPacketProtectionMaterial retainedPhaseTwoOpenMaterial =
                runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial!.Value;
            QuicTlsPacketProtectionMaterial phaseThreeOpenMaterial =
                runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value;

            QuicHandshakeFlowCoordinator peerCoordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();
            SkipPacketNumbers(peerCoordinator, phaseThreeOpenMaterial, keyPhase: true, count: 8);
            Assert.True(peerCoordinator.TryBuildProtectedApplicationDataPacket(
                CreateAckElicitingPayload(random.Next(1, 96)),
                retainedPhaseTwoOpenMaterial,
                keyPhase: false,
                out ulong oldPacketNumber,
                out byte[] oldProtectedPacket));
            Assert.True(peerCoordinator.TryBuildProtectedApplicationDataPacket(
                CreateAckElicitingPayload(random.Next(1, 96)),
                phaseThreeOpenMaterial,
                keyPhase: true,
                out ulong currentPacketNumber,
                out byte[] currentProtectedPacket));

            _ = runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: 50_000 + (iteration * 2),
                    QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                    currentProtectedPacket),
                nowTicks: 50_000 + (iteration * 2));
            _ = runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: 60_000 + (iteration * 2),
                    QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                    oldProtectedPacket),
                nowTicks: 60_000 + (iteration * 2));

            Assert.True(currentPacketNumber > oldPacketNumber);
            Assert.True(TryBuildApplicationAckFrame(runtime, 60_000 + (iteration * 2), out QuicAckFrame ackFrame));
            Assert.Equal(currentPacketNumber, ackFrame.LargestAcknowledged);
            Assert.Equal(currentPacketNumber - oldPacketNumber, ackFrame.FirstAckRange);
            Assert.Equal(3U, runtime.TlsState.CurrentOneRttKeyPhase);
            Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
            Assert.Null(runtime.TerminalState);
            Assert.Null(runtime.TlsState.FatalAlertCode);
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzPhaseFourLowerRecoveredPackets_UsePreviousPhaseThreeKeysAcrossRepresentativePayloadSizes()
    {
        Random random = new(unchecked((int)0x9001_6514));

        for (int iteration = 0; iteration < 32; iteration++)
        {
            using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
            QuicRfc9001RepeatedKeyUpdateTestSupport.PrepareLocalPhaseFourWithPhaseThreeRetained(runtime);

            QuicTlsPacketProtectionMaterial retainedPhaseThreeOpenMaterial =
                runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial!.Value;
            QuicTlsPacketProtectionMaterial phaseFourOpenMaterial =
                runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value;

            QuicHandshakeFlowCoordinator peerCoordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();
            SkipPacketNumbers(peerCoordinator, phaseFourOpenMaterial, keyPhase: false, count: 8);
            Assert.True(peerCoordinator.TryBuildProtectedApplicationDataPacket(
                CreateAckElicitingPayload(random.Next(1, 96)),
                retainedPhaseThreeOpenMaterial,
                keyPhase: true,
                out ulong oldPacketNumber,
                out byte[] oldProtectedPacket));
            Assert.True(peerCoordinator.TryBuildProtectedApplicationDataPacket(
                CreateAckElicitingPayload(random.Next(1, 96)),
                phaseFourOpenMaterial,
                keyPhase: false,
                out ulong currentPacketNumber,
                out byte[] currentProtectedPacket));

            _ = runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: 70_000 + (iteration * 2),
                    QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                    currentProtectedPacket),
                nowTicks: 70_000 + (iteration * 2));
            _ = runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: 80_000 + (iteration * 2),
                    QuicRfc9001KeyPhaseTestSupport.PacketPathIdentity,
                    oldProtectedPacket),
                nowTicks: 80_000 + (iteration * 2));

            Assert.True(currentPacketNumber > oldPacketNumber);
            Assert.True(TryBuildApplicationAckFrame(runtime, 80_000 + (iteration * 2), out QuicAckFrame ackFrame));
            Assert.Equal(currentPacketNumber, ackFrame.LargestAcknowledged);
            Assert.Equal(currentPacketNumber - oldPacketNumber, ackFrame.FirstAckRange);
            Assert.Equal(4U, runtime.TlsState.CurrentOneRttKeyPhase);
            Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
            Assert.Null(runtime.TerminalState);
            Assert.Null(runtime.TlsState.FatalAlertCode);
        }
    }

    private static void AssertRuntimeUsesPreviousKeysForLowerRecoveredPacketNumbers(
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
        AssertPacketRequiresOldKeys(oldProtectedPacket, currentOpenMaterial, retainedOldOpenMaterial);

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
                oldProtectedPacket),
            nowTicks: 20_000);

        Assert.True(TryBuildApplicationAckFrame(runtime, 20_000, out QuicAckFrame ackFrame));
        Assert.Equal(currentPacketNumber, ackFrame.LargestAcknowledged);
        Assert.Equal(currentPacketNumber - oldPacketNumber, ackFrame.FirstAckRange);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.Null(runtime.TerminalState);
        Assert.Null(runtime.TlsState.FatalAlertCode);
    }

    private static void AssertPacketRequiresOldKeys(
        byte[] protectedPacket,
        QuicTlsPacketProtectionMaterial currentOpenMaterial,
        QuicTlsPacketProtectionMaterial retainedOldOpenMaterial,
        bool expectedRetainedOldKeyPhase = false)
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
            retainedOldOpenMaterial,
            out _,
            out _,
            out _,
            out bool observedKeyPhase));
        Assert.Equal(expectedRetainedOldKeyPhase, observedKeyPhase);
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

    private static void InstallRepeatedLocalUpdate(QuicConnectionRuntime runtime)
    {
        QuicRfc9001RepeatedKeyUpdateTestSupport.ConfigureRuntime(runtime);
        ulong repeatedUpdateNotBeforeMicros =
            QuicRfc9001RepeatedKeyUpdateTestSupport.PrepareRepeatedLocalUpdateEligibility(runtime);
        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryInstallRuntimeRepeatedOneRttKeyUpdate(
            runtime,
            repeatedUpdateNotBeforeMicros));
        Assert.Equal(2U, runtime.TlsState.CurrentOneRttKeyPhase);
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
