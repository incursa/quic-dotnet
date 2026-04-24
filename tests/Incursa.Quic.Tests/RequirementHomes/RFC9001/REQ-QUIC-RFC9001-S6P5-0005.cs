using System.Diagnostics;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual trace slice">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S6P5-0005">After the old-read-key retention window expires, an endpoint SHOULD discard the old read keys and their corresponding secrets.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9001-S6P5-0005")]
public sealed class REQ_QUIC_RFC9001_S6P5_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveClientRuntimeDiscardsOldReadKeysAndOldPhaseSendStateWhenTheRetentionTimerExpires()
    {
        AssertRuntimeDiscardsOldReadKeysAndOldPhaseSendStateWhenTheRetentionTimerExpires(
            QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveServerRuntimeDiscardsOldReadKeysAndOldPhaseSendStateWhenTheRetentionTimerExpires()
    {
        AssertRuntimeDiscardsOldReadKeysAndOldPhaseSendStateWhenTheRetentionTimerExpires(
            () => QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RecoveryControllerDiscardsOnlyTheSpecifiedOneRttKeyPhase()
    {
        QuicRecoveryController controller = new();
        controller.RecordPacketSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 1,
            sentAtMicros: 100,
            isAckElicitingPacket: true,
            packetProtectionLevel: QuicTlsEncryptionLevel.OneRtt,
            oneRttKeyPhase: 0);
        controller.RecordPacketSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 2,
            sentAtMicros: 200,
            isAckElicitingPacket: true,
            packetProtectionLevel: QuicTlsEncryptionLevel.OneRtt,
            oneRttKeyPhase: 1);

        Assert.True(controller.TryDiscardOneRttKeyPhase(0));
        Assert.True(controller.TrySelectLossDetectionTimer(
            nowMicros: 300,
            maxAckDelayMicros: 25_000,
            handshakeConfirmed: true,
            serverAtAntiAmplificationLimit: false,
            peerAddressValidationComplete: true,
            handshakeKeysAvailable: true,
            out _,
            out QuicPacketNumberSpace selectedPacketNumberSpace));
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, selectedPacketNumberSpace);

        Assert.True(controller.TryDiscardOneRttKeyPhase(1));
        Assert.False(controller.TrySelectLossDetectionTimer(
            nowMicros: 400,
            maxAckDelayMicros: 25_000,
            handshakeConfirmed: true,
            serverAtAntiAmplificationLimit: false,
            peerAddressValidationComplete: true,
            handshakeKeysAvailable: true,
            out _,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ActiveClientRuntimeKeepsOldReadKeysAndOldPhaseSendStateBeforeTheRetentionTimerExpires()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001KeyUpdateRetentionTestSupport.ConfigureRuntime(runtime);

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryInstallRuntimeOneRttKeyUpdate(runtime));
        QuicRfc9001KeyUpdateRetentionTestSupport.SeedTrackedOneRttPacket(runtime, packetNumber: 10, sentAtMicros: 100, keyPhase: 0);
        QuicRfc9001KeyUpdateRetentionTestSupport.SeedTrackedOneRttPacket(runtime, packetNumber: 11, sentAtMicros: 200, keyPhase: 1);

        QuicConnectionTransitionResult armResult =
            QuicRfc9001KeyUpdateRetentionTestSupport.ReceiveCurrentPhaseOnePacket(runtime, observedAtTicks: 1);

        Assert.True(armResult.StateChanged);
        Assert.NotNull(runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial);
        Assert.NotNull(runtime.TlsState.RetainedOldOneRttProtectPacketProtectionMaterial);
        Assert.Contains(runtime.SendRuntime.SentPackets.Values, packet => packet.OneRttKeyPhase == 0);
        Assert.Contains(runtime.SendRuntime.SentPackets.Values, packet => packet.OneRttKeyPhase == 1);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveClientRuntimePreservesCurrentPhaseAcknowledgmentGateWhenRetainedOldKeysExpire()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001RepeatedKeyUpdateTestSupport.ConfigureRuntime(runtime);

        ulong phaseTwoNotBeforeMicros = QuicRfc9001RepeatedKeyUpdateTestSupport.PrepareRepeatedLocalUpdateEligibility(runtime);
        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryInstallRuntimeRepeatedOneRttKeyUpdate(
            runtime,
            phaseTwoNotBeforeMicros));
        Assert.Equal(2U, runtime.TlsState.CurrentOneRttKeyPhase);

        QuicRfc9001KeyUpdateRetentionTestSupport.SeedTrackedOneRttPacket(
            runtime,
            packetNumber: 42,
            sentAtMicros: 420,
            keyPhase: runtime.TlsState.CurrentOneRttKeyPhase);

        QuicConnectionTransitionResult ackResult =
            QuicRfc9001RepeatedKeyUpdateTestSupport.ReceiveCurrentPhaseAck(
                runtime,
                largestAcknowledged: 42,
                observedAtTicks: Stopwatch.Frequency * 3L);

        Assert.True(ackResult.StateChanged);
        Assert.True(runtime.TlsState.CurrentOneRttKeyPhaseAcknowledged);
        Assert.True(runtime.TlsState.RetainedOldOneRttPacketProtectionDiscardAtMicros.HasValue);
        ulong phaseThreeNotBeforeMicros = runtime.TlsState.RepeatedLocalOneRttKeyUpdateNotBeforeMicros!.Value;

        QuicConnectionTransitionResult timerResult =
            QuicRfc9001KeyUpdateRetentionTestSupport.ExpireKeyUpdateRetentionTimer(runtime);

        Assert.True(timerResult.StateChanged);
        Assert.Null(runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial);
        Assert.Null(runtime.TlsState.RetainedOldOneRttProtectPacketProtectionMaterial);
        Assert.True(runtime.TlsState.CurrentOneRttKeyPhaseAcknowledged);
        Assert.Equal(phaseThreeNotBeforeMicros, runtime.TlsState.RepeatedLocalOneRttKeyUpdateNotBeforeMicros);
        Assert.True(runtime.TlsState.CanInitiateRepeatedLocalOneRttKeyUpdate(phaseThreeNotBeforeMicros));
        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryInstallRuntimeRepeatedOneRttKeyUpdate(
            runtime,
            phaseThreeNotBeforeMicros));
        Assert.Equal(3U, runtime.TlsState.CurrentOneRttKeyPhase);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveClientRuntimeDiscardsRetainedPhaseOneReadKeysAndPhaseOneSendStateAfterRepeatedLocalKeyUpdate()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        PrepareRepeatedLocalPhaseTwoWithPhaseOneRetained(runtime);
        SeedRepeatedPhaseTrackedPackets(runtime);

        QuicConnectionTransitionResult armResult =
            QuicRfc9001KeyUpdateRetentionTestSupport.ReceiveCurrentPhasePacket(
                runtime,
                observedAtTicks: Stopwatch.Frequency * 3L);

        Assert.True(armResult.StateChanged);
        Assert.Equal(1U, runtime.TlsState.RetainedOldOneRttPacketProtectionKeyPhase);
        Assert.Equal(1, runtime.SendRuntime.PendingRetransmissionCount);

        QuicConnectionTransitionResult timerResult =
            QuicRfc9001KeyUpdateRetentionTestSupport.ExpireKeyUpdateRetentionTimer(runtime);

        AssertRepeatedPhaseOneDiscardedAndPhaseTwoRetained(runtime, timerResult);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveClientRuntimeDiscardsRetainedPhaseTwoReadKeysAndPhaseTwoSendStateAfterPhaseThreeLocalKeyUpdate()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001RepeatedKeyUpdateTestSupport.PrepareLocalPhaseThreeWithPhaseTwoRetained(runtime);
        SeedPhaseThreeTrackedPackets(runtime);

        QuicConnectionTransitionResult armResult =
            QuicRfc9001KeyUpdateRetentionTestSupport.ReceiveCurrentPhasePacket(
                runtime,
                observedAtTicks: Stopwatch.Frequency * 5L);

        Assert.True(armResult.StateChanged);
        Assert.Equal(2U, runtime.TlsState.RetainedOldOneRttPacketProtectionKeyPhase);
        Assert.Equal(1, runtime.SendRuntime.PendingRetransmissionCount);

        QuicConnectionTransitionResult timerResult =
            QuicRfc9001KeyUpdateRetentionTestSupport.ExpireKeyUpdateRetentionTimer(runtime);

        AssertRepeatedPhaseTwoDiscardedAndPhaseThreeRetained(runtime, timerResult);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveClientRuntimeDiscardsRetainedPhaseThreeReadKeysAndPhaseThreeSendStateAfterPhaseFourLocalKeyUpdate()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001RepeatedKeyUpdateTestSupport.PrepareLocalPhaseFourWithPhaseThreeRetained(runtime);
        SeedPhaseFourTrackedPackets(runtime);

        QuicConnectionTransitionResult armResult =
            QuicRfc9001KeyUpdateRetentionTestSupport.ReceiveCurrentPhasePacket(
                runtime,
                observedAtTicks: Stopwatch.Frequency * 7L);

        Assert.True(armResult.StateChanged);
        Assert.Equal(3U, runtime.TlsState.RetainedOldOneRttPacketProtectionKeyPhase);
        Assert.Equal(1, runtime.SendRuntime.PendingRetransmissionCount);

        QuicConnectionTransitionResult timerResult =
            QuicRfc9001KeyUpdateRetentionTestSupport.ExpireKeyUpdateRetentionTimer(runtime);

        AssertRepeatedPhaseThreeDiscardedAndPhaseFourRetained(runtime, timerResult);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveClientRuntimeDiscardsRetainedPhaseFourReadKeysAndPhaseFourSendStateAfterPhaseFiveLocalKeyUpdate()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001RepeatedKeyUpdateTestSupport.PrepareLocalPhaseFiveWithPhaseFourRetained(runtime);
        SeedPhaseFiveTrackedPackets(runtime);

        QuicConnectionTransitionResult armResult =
            QuicRfc9001KeyUpdateRetentionTestSupport.ReceiveCurrentPhasePacket(
                runtime,
                observedAtTicks: Stopwatch.Frequency * 9L);

        Assert.True(armResult.StateChanged);
        Assert.Equal(4U, runtime.TlsState.RetainedOldOneRttPacketProtectionKeyPhase);
        Assert.Equal(1, runtime.SendRuntime.PendingRetransmissionCount);

        QuicConnectionTransitionResult timerResult =
            QuicRfc9001KeyUpdateRetentionTestSupport.ExpireKeyUpdateRetentionTimer(runtime);

        AssertRepeatedPhaseFourDiscardedAndPhaseFiveRetained(runtime, timerResult);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveClientRuntimeDiscardsRetainedPhaseOneReadKeysAndPhaseOneSendStateAfterRepeatedPeerKeyUpdate()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001RepeatedKeyUpdateTestSupport.PrepareRepeatedPeerUpdateEligibility(
            runtime,
            out QuicTlsPacketProtectionMaterial secondSuccessorOpenMaterial,
            out _);

        QuicRfc9001KeyUpdateRetentionTestSupport.SeedTrackedOneRttPacket(
            runtime,
            packetNumber: 30,
            sentAtMicros: 300,
            keyPhase: 1);
        QuicRfc9001KeyUpdateRetentionTestSupport.SeedLostOneRttPacket(
            runtime,
            packetNumber: 31,
            sentAtMicros: 310,
            keyPhase: 1);

        QuicConnectionTransitionResult armResult = QuicRfc9001RepeatedKeyUpdateTestSupport.ReceivePeerUpdatePacket(
            runtime,
            secondSuccessorOpenMaterial,
            keyPhase: false,
            observedAtTicks: Stopwatch.Frequency * 3L,
            QuicRfc9001KeyPhaseTestSupport.CreatePingPayload());

        Assert.True(armResult.StateChanged);
        Assert.Equal(2U, runtime.TlsState.CurrentOneRttKeyPhase);
        Assert.Equal(1U, runtime.TlsState.RetainedOldOneRttPacketProtectionKeyPhase);

        QuicRfc9001KeyUpdateRetentionTestSupport.SeedTrackedOneRttPacket(
            runtime,
            packetNumber: 32,
            sentAtMicros: 320,
            keyPhase: 2);
        Assert.Equal(1, runtime.SendRuntime.PendingRetransmissionCount);

        QuicConnectionTransitionResult timerResult =
            QuicRfc9001KeyUpdateRetentionTestSupport.ExpireKeyUpdateRetentionTimer(runtime);

        AssertRepeatedPhaseOneDiscardedAndPhaseTwoRetained(runtime, timerResult);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ActiveClientRuntimeKeepsRetainedPhaseOneStateBeforeRepeatedRetentionTimerExpires()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        PrepareRepeatedLocalPhaseTwoWithPhaseOneRetained(runtime);
        SeedRepeatedPhaseTrackedPackets(runtime);

        QuicConnectionTransitionResult armResult =
            QuicRfc9001KeyUpdateRetentionTestSupport.ReceiveCurrentPhasePacket(
                runtime,
                observedAtTicks: Stopwatch.Frequency * 3L);

        Assert.True(armResult.StateChanged);
        Assert.NotNull(runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial);
        Assert.NotNull(runtime.TlsState.RetainedOldOneRttProtectPacketProtectionMaterial);
        Assert.Equal(1U, runtime.TlsState.RetainedOldOneRttPacketProtectionKeyPhase);
        Assert.Contains(runtime.SendRuntime.SentPackets.Values, packet => packet.OneRttKeyPhase == 1);
        Assert.Contains(runtime.SendRuntime.SentPackets.Values, packet => packet.OneRttKeyPhase == 2);
        Assert.Equal(1, runtime.SendRuntime.PendingRetransmissionCount);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzRetentionExpiry_DiscardsOnlyTheOldOneRttKeyPhaseAcrossRepresentativePacketSets()
    {
        Random random = new(unchecked((int)0x9001_6505));

        for (int iteration = 0; iteration < 32; iteration++)
        {
            using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
            QuicRfc9001KeyUpdateRetentionTestSupport.ConfigureRuntime(runtime);

            Assert.True(QuicRfc9001KeyPhaseTestSupport.TryInstallRuntimeOneRttKeyUpdate(runtime));

            int oldPacketCount = random.Next(1, 4);
            int currentPacketCount = random.Next(1, 4);
            for (int index = 0; index < oldPacketCount; index++)
            {
                QuicRfc9001KeyUpdateRetentionTestSupport.SeedTrackedOneRttPacket(
                    runtime,
                    packetNumber: (ulong)(10 + index),
                    sentAtMicros: (ulong)(100 + index),
                    keyPhase: 0);
            }

            for (int index = 0; index < currentPacketCount; index++)
            {
                QuicRfc9001KeyUpdateRetentionTestSupport.SeedTrackedOneRttPacket(
                    runtime,
                    packetNumber: (ulong)(20 + index),
                    sentAtMicros: (ulong)(200 + index),
                    keyPhase: 1);
            }

            QuicRfc9001KeyUpdateRetentionTestSupport.SeedLostOneRttPacket(
                runtime,
                packetNumber: (ulong)(50 + iteration),
                sentAtMicros: (ulong)(300 + iteration),
                keyPhase: 0);
            _ = QuicRfc9001KeyUpdateRetentionTestSupport.ReceiveCurrentPhaseOnePacket(runtime, observedAtTicks: iteration + 1);
            QuicConnectionTransitionResult timerResult =
                QuicRfc9001KeyUpdateRetentionTestSupport.ExpireKeyUpdateRetentionTimer(runtime);

            Assert.True(timerResult.StateChanged);
            Assert.Null(runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial);
            Assert.Null(runtime.TlsState.RetainedOldOneRttProtectPacketProtectionMaterial);
            Assert.DoesNotContain(runtime.SendRuntime.SentPackets.Values, packet => packet.OneRttKeyPhase == 0);
            Assert.Contains(runtime.SendRuntime.SentPackets.Values, packet => packet.OneRttKeyPhase == 1);
            Assert.Equal(0, runtime.SendRuntime.PendingRetransmissionCount);
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzRepeatedRetentionExpiry_DiscardsOnlyRetainedPhaseOneAcrossRepresentativePacketSets()
    {
        Random random = new(unchecked((int)0x9001_6515));

        for (int iteration = 0; iteration < 32; iteration++)
        {
            using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
            PrepareRepeatedLocalPhaseTwoWithPhaseOneRetained(runtime);

            int retainedPhaseOnePacketCount = random.Next(1, 4);
            int currentPhaseTwoPacketCount = random.Next(1, 4);
            for (int index = 0; index < retainedPhaseOnePacketCount; index++)
            {
                QuicRfc9001KeyUpdateRetentionTestSupport.SeedTrackedOneRttPacket(
                    runtime,
                    packetNumber: (ulong)(30 + index),
                    sentAtMicros: (ulong)(300 + index),
                    keyPhase: 1);
            }

            for (int index = 0; index < currentPhaseTwoPacketCount; index++)
            {
                QuicRfc9001KeyUpdateRetentionTestSupport.SeedTrackedOneRttPacket(
                    runtime,
                    packetNumber: (ulong)(70 + index),
                    sentAtMicros: (ulong)(700 + index),
                    keyPhase: 2);
            }

            QuicRfc9001KeyUpdateRetentionTestSupport.SeedLostOneRttPacket(
                runtime,
                packetNumber: (ulong)(110 + iteration),
                sentAtMicros: (ulong)(900 + iteration),
                keyPhase: 1);
            _ = QuicRfc9001KeyUpdateRetentionTestSupport.ReceiveCurrentPhasePacket(
                runtime,
                observedAtTicks: Stopwatch.Frequency * (3L + iteration));
            QuicConnectionTransitionResult timerResult =
                QuicRfc9001KeyUpdateRetentionTestSupport.ExpireKeyUpdateRetentionTimer(runtime);

            Assert.True(timerResult.StateChanged);
            Assert.Null(runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial);
            Assert.Null(runtime.TlsState.RetainedOldOneRttProtectPacketProtectionMaterial);
            Assert.DoesNotContain(runtime.SendRuntime.SentPackets.Values, packet => packet.OneRttKeyPhase == 1);
            Assert.Contains(runtime.SendRuntime.SentPackets.Values, packet => packet.OneRttKeyPhase == 2);
            Assert.Equal(0, runtime.SendRuntime.PendingRetransmissionCount);
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzPhaseThreeRetentionExpiry_DiscardsOnlyRetainedPhaseTwoAcrossRepresentativePacketSets()
    {
        Random random = new(unchecked((int)0x9001_6525));

        for (int iteration = 0; iteration < 32; iteration++)
        {
            using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
            QuicRfc9001RepeatedKeyUpdateTestSupport.PrepareLocalPhaseThreeWithPhaseTwoRetained(runtime);

            int retainedPhaseTwoPacketCount = random.Next(1, 4);
            int currentPhaseThreePacketCount = random.Next(1, 4);
            for (int index = 0; index < retainedPhaseTwoPacketCount; index++)
            {
                QuicRfc9001KeyUpdateRetentionTestSupport.SeedTrackedOneRttPacket(
                    runtime,
                    packetNumber: (ulong)(130 + index),
                    sentAtMicros: (ulong)(1_300 + index),
                    keyPhase: 2);
            }

            for (int index = 0; index < currentPhaseThreePacketCount; index++)
            {
                QuicRfc9001KeyUpdateRetentionTestSupport.SeedTrackedOneRttPacket(
                    runtime,
                    packetNumber: (ulong)(170 + index),
                    sentAtMicros: (ulong)(1_700 + index),
                    keyPhase: 3);
            }

            QuicRfc9001KeyUpdateRetentionTestSupport.SeedLostOneRttPacket(
                runtime,
                packetNumber: (ulong)(210 + iteration),
                sentAtMicros: (ulong)(2_100 + iteration),
                keyPhase: 2);
            _ = QuicRfc9001KeyUpdateRetentionTestSupport.ReceiveCurrentPhasePacket(
                runtime,
                observedAtTicks: Stopwatch.Frequency * (5L + iteration));
            QuicConnectionTransitionResult timerResult =
                QuicRfc9001KeyUpdateRetentionTestSupport.ExpireKeyUpdateRetentionTimer(runtime);

            Assert.True(timerResult.StateChanged);
            Assert.Null(runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial);
            Assert.Null(runtime.TlsState.RetainedOldOneRttProtectPacketProtectionMaterial);
            Assert.DoesNotContain(runtime.SendRuntime.SentPackets.Values, packet => packet.OneRttKeyPhase == 2);
            Assert.Contains(runtime.SendRuntime.SentPackets.Values, packet => packet.OneRttKeyPhase == 3);
            Assert.Equal(0, runtime.SendRuntime.PendingRetransmissionCount);
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzPhaseFourRetentionExpiry_DiscardsOnlyRetainedPhaseThreeAcrossRepresentativePacketSets()
    {
        Random random = new(unchecked((int)0x9001_6535));

        for (int iteration = 0; iteration < 32; iteration++)
        {
            using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
            QuicRfc9001RepeatedKeyUpdateTestSupport.PrepareLocalPhaseFourWithPhaseThreeRetained(runtime);

            int retainedPhaseThreePacketCount = random.Next(1, 4);
            int currentPhaseFourPacketCount = random.Next(1, 4);
            for (int index = 0; index < retainedPhaseThreePacketCount; index++)
            {
                QuicRfc9001KeyUpdateRetentionTestSupport.SeedTrackedOneRttPacket(
                    runtime,
                    packetNumber: (ulong)(230 + index),
                    sentAtMicros: (ulong)(2_300 + index),
                    keyPhase: 3);
            }

            for (int index = 0; index < currentPhaseFourPacketCount; index++)
            {
                QuicRfc9001KeyUpdateRetentionTestSupport.SeedTrackedOneRttPacket(
                    runtime,
                    packetNumber: (ulong)(270 + index),
                    sentAtMicros: (ulong)(2_700 + index),
                    keyPhase: 4);
            }

            QuicRfc9001KeyUpdateRetentionTestSupport.SeedLostOneRttPacket(
                runtime,
                packetNumber: (ulong)(310 + iteration),
                sentAtMicros: (ulong)(3_100 + iteration),
                keyPhase: 3);
            _ = QuicRfc9001KeyUpdateRetentionTestSupport.ReceiveCurrentPhasePacket(
                runtime,
                observedAtTicks: Stopwatch.Frequency * (7L + iteration));
            QuicConnectionTransitionResult timerResult =
                QuicRfc9001KeyUpdateRetentionTestSupport.ExpireKeyUpdateRetentionTimer(runtime);

            Assert.True(timerResult.StateChanged);
            Assert.Null(runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial);
            Assert.Null(runtime.TlsState.RetainedOldOneRttProtectPacketProtectionMaterial);
            Assert.DoesNotContain(runtime.SendRuntime.SentPackets.Values, packet => packet.OneRttKeyPhase == 3);
            Assert.Contains(runtime.SendRuntime.SentPackets.Values, packet => packet.OneRttKeyPhase == 4);
            Assert.Equal(0, runtime.SendRuntime.PendingRetransmissionCount);
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzPhaseFiveRetentionExpiry_DiscardsOnlyRetainedPhaseFourAcrossRepresentativePacketSets()
    {
        Random random = new(unchecked((int)0x9001_6545));

        for (int iteration = 0; iteration < 32; iteration++)
        {
            using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
            QuicRfc9001RepeatedKeyUpdateTestSupport.PrepareLocalPhaseFiveWithPhaseFourRetained(runtime);

            int retainedPhaseFourPacketCount = random.Next(1, 4);
            int currentPhaseFivePacketCount = random.Next(1, 4);
            for (int index = 0; index < retainedPhaseFourPacketCount; index++)
            {
                QuicRfc9001KeyUpdateRetentionTestSupport.SeedTrackedOneRttPacket(
                    runtime,
                    packetNumber: (ulong)(330 + index),
                    sentAtMicros: (ulong)(3_300 + index),
                    keyPhase: 4);
            }

            for (int index = 0; index < currentPhaseFivePacketCount; index++)
            {
                QuicRfc9001KeyUpdateRetentionTestSupport.SeedTrackedOneRttPacket(
                    runtime,
                    packetNumber: (ulong)(370 + index),
                    sentAtMicros: (ulong)(3_700 + index),
                    keyPhase: 5);
            }

            QuicRfc9001KeyUpdateRetentionTestSupport.SeedLostOneRttPacket(
                runtime,
                packetNumber: (ulong)(410 + iteration),
                sentAtMicros: (ulong)(4_100 + iteration),
                keyPhase: 4);
            _ = QuicRfc9001KeyUpdateRetentionTestSupport.ReceiveCurrentPhasePacket(
                runtime,
                observedAtTicks: Stopwatch.Frequency * (9L + iteration));
            QuicConnectionTransitionResult timerResult =
                QuicRfc9001KeyUpdateRetentionTestSupport.ExpireKeyUpdateRetentionTimer(runtime);

            Assert.True(timerResult.StateChanged);
            Assert.Null(runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial);
            Assert.Null(runtime.TlsState.RetainedOldOneRttProtectPacketProtectionMaterial);
            Assert.DoesNotContain(runtime.SendRuntime.SentPackets.Values, packet => packet.OneRttKeyPhase == 4);
            Assert.Contains(runtime.SendRuntime.SentPackets.Values, packet => packet.OneRttKeyPhase == 5);
            Assert.Equal(0, runtime.SendRuntime.PendingRetransmissionCount);
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzLaterRetentionExpiry_DiscardsOnlyTheRetainedPreviousPhaseAcrossRepresentativePacketSets()
    {
        Random random = new(unchecked((int)0x9001_6555));

        for (int iteration = 0; iteration < 16; iteration++)
        {
            uint targetPhase = (uint)random.Next(6, 33);
            uint retainedPreviousPhase = targetPhase - 1U;
            using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
            QuicRfc9001RepeatedKeyUpdateTestSupport.ConfigureRuntime(runtime);
            QuicRfc9001RepeatedKeyUpdateTestSupport.PrepareLocalPhaseWithPreviousRetained(
                runtime,
                targetPhase);

            int retainedPreviousPacketCount = random.Next(1, 4);
            int currentPhasePacketCount = random.Next(1, 4);
            for (int index = 0; index < retainedPreviousPacketCount; index++)
            {
                QuicRfc9001KeyUpdateRetentionTestSupport.SeedTrackedOneRttPacket(
                    runtime,
                    packetNumber: (ulong)(530 + index),
                    sentAtMicros: (ulong)(5_300 + index),
                    keyPhase: retainedPreviousPhase);
            }

            for (int index = 0; index < currentPhasePacketCount; index++)
            {
                QuicRfc9001KeyUpdateRetentionTestSupport.SeedTrackedOneRttPacket(
                    runtime,
                    packetNumber: (ulong)(570 + index),
                    sentAtMicros: (ulong)(5_700 + index),
                    keyPhase: targetPhase);
            }

            QuicRfc9001KeyUpdateRetentionTestSupport.SeedLostOneRttPacket(
                runtime,
                packetNumber: (ulong)(610 + iteration),
                sentAtMicros: (ulong)(6_100 + iteration),
                keyPhase: retainedPreviousPhase);
            _ = QuicRfc9001KeyUpdateRetentionTestSupport.ReceiveCurrentPhasePacket(
                runtime,
                observedAtTicks: Stopwatch.Frequency * (long)(targetPhase + 5U));
            QuicConnectionTransitionResult timerResult =
                QuicRfc9001KeyUpdateRetentionTestSupport.ExpireKeyUpdateRetentionTimer(runtime);

            Assert.True(timerResult.StateChanged);
            Assert.Null(runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial);
            Assert.Null(runtime.TlsState.RetainedOldOneRttProtectPacketProtectionMaterial);
            Assert.DoesNotContain(
                runtime.SendRuntime.SentPackets.Values,
                packet => packet.OneRttKeyPhase == retainedPreviousPhase);
            Assert.Contains(runtime.SendRuntime.SentPackets.Values, packet => packet.OneRttKeyPhase == targetPhase);
            Assert.Equal(0, runtime.SendRuntime.PendingRetransmissionCount);
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzLaterRetentionExpiry_PreservesCurrentPhaseGateAcrossSampledEpochs()
    {
        Random random = new(unchecked((int)0x9001_6565));

        for (int iteration = 0; iteration < 8; iteration++)
        {
            uint targetPhase = (uint)random.Next(6, 33);
            ulong packetNumber = 900UL + (ulong)iteration;
            using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
            QuicRfc9001RepeatedKeyUpdateTestSupport.ConfigureRuntime(runtime);
            QuicRfc9001RepeatedKeyUpdateTestSupport.PrepareLocalPhaseWithPreviousRetained(
                runtime,
                targetPhase);

            QuicRfc9001KeyUpdateRetentionTestSupport.SeedTrackedOneRttPacket(
                runtime,
                packetNumber,
                sentAtMicros: 9_000UL + (ulong)iteration,
                keyPhase: targetPhase);

            long observedAtTicks = Stopwatch.Frequency * (long)(targetPhase + 8U);
            QuicConnectionTransitionResult ackResult =
                QuicRfc9001RepeatedKeyUpdateTestSupport.ReceiveCurrentPhaseAck(
                    runtime,
                    largestAcknowledged: packetNumber,
                    observedAtTicks);

            Assert.True(ackResult.StateChanged);
            Assert.True(runtime.TlsState.CurrentOneRttKeyPhaseAcknowledged);
            Assert.Equal(targetPhase - 1U, runtime.TlsState.RetainedOldOneRttPacketProtectionKeyPhase);
            ulong nextNotBeforeMicros = runtime.TlsState.RepeatedLocalOneRttKeyUpdateNotBeforeMicros!.Value;

            QuicConnectionTransitionResult timerResult =
                QuicRfc9001KeyUpdateRetentionTestSupport.ExpireKeyUpdateRetentionTimer(runtime);

            Assert.True(timerResult.StateChanged);
            Assert.Null(runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial);
            Assert.Null(runtime.TlsState.RetainedOldOneRttProtectPacketProtectionMaterial);
            Assert.True(runtime.TlsState.CurrentOneRttKeyPhaseAcknowledged);
            Assert.Equal(nextNotBeforeMicros, runtime.TlsState.RepeatedLocalOneRttKeyUpdateNotBeforeMicros);
            Assert.True(runtime.TlsState.CanInitiateRepeatedLocalOneRttKeyUpdate(nextNotBeforeMicros));
            Assert.True(QuicRfc9001KeyPhaseTestSupport.TryInstallRuntimeRepeatedOneRttKeyUpdate(
                runtime,
                nextNotBeforeMicros));
            Assert.Equal(targetPhase + 1U, runtime.TlsState.CurrentOneRttKeyPhase);
        }
    }

    private static void AssertRuntimeDiscardsOldReadKeysAndOldPhaseSendStateWhenTheRetentionTimerExpires(
        Func<QuicConnectionRuntime> runtimeFactory)
    {
        using QuicConnectionRuntime runtime = runtimeFactory();
        QuicRfc9001KeyUpdateRetentionTestSupport.ConfigureRuntime(runtime);

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryInstallRuntimeOneRttKeyUpdate(runtime));
        QuicRfc9001KeyUpdateRetentionTestSupport.SeedTrackedOneRttPacket(runtime, packetNumber: 10, sentAtMicros: 100, keyPhase: 0);
        QuicRfc9001KeyUpdateRetentionTestSupport.SeedLostOneRttPacket(runtime, packetNumber: 11, sentAtMicros: 110, keyPhase: 0);
        QuicRfc9001KeyUpdateRetentionTestSupport.SeedTrackedOneRttPacket(runtime, packetNumber: 12, sentAtMicros: 120, keyPhase: 1);

        QuicConnectionTransitionResult armResult =
            QuicRfc9001KeyUpdateRetentionTestSupport.ReceiveCurrentPhaseOnePacket(runtime, observedAtTicks: 1);

        Assert.True(armResult.StateChanged);
        Assert.NotNull(runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial);
        Assert.NotNull(runtime.TlsState.RetainedOldOneRttProtectPacketProtectionMaterial);
        Assert.Equal(1, runtime.SendRuntime.PendingRetransmissionCount);

        QuicConnectionTransitionResult timerResult =
            QuicRfc9001KeyUpdateRetentionTestSupport.ExpireKeyUpdateRetentionTimer(runtime);
        QuicRecoveryController recoveryController =
            QuicRfc9001KeyUpdateRetentionTestSupport.GetRecoveryController(runtime);

        Assert.True(timerResult.StateChanged);
        Assert.Null(runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial);
        Assert.Null(runtime.TlsState.RetainedOldOneRttProtectPacketProtectionMaterial);
        Assert.True(runtime.TlsState.OneRttOpenPacketProtectionMaterial.HasValue);
        Assert.True(runtime.TlsState.OneRttProtectPacketProtectionMaterial.HasValue);
        Assert.DoesNotContain(runtime.SendRuntime.SentPackets.Values, packet => packet.OneRttKeyPhase == 0);
        Assert.Contains(runtime.SendRuntime.SentPackets.Values, packet => packet.OneRttKeyPhase == 1);
        Assert.Equal(0, runtime.SendRuntime.PendingRetransmissionCount);
        Assert.True(recoveryController.TrySelectLossDetectionTimer(
            nowMicros: 500,
            maxAckDelayMicros: 25_000,
            handshakeConfirmed: true,
            serverAtAntiAmplificationLimit: false,
            peerAddressValidationComplete: true,
            handshakeKeysAvailable: true,
            out _,
            out QuicPacketNumberSpace selectedPacketNumberSpace));
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, selectedPacketNumberSpace);
    }

    private static void PrepareRepeatedLocalPhaseTwoWithPhaseOneRetained(QuicConnectionRuntime runtime)
    {
        QuicRfc9001RepeatedKeyUpdateTestSupport.ConfigureRuntime(runtime);
        ulong notBeforeMicros = QuicRfc9001RepeatedKeyUpdateTestSupport.PrepareRepeatedLocalUpdateEligibility(runtime);

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryInstallRuntimeRepeatedOneRttKeyUpdate(runtime, notBeforeMicros));
        Assert.Equal(2U, runtime.TlsState.CurrentOneRttKeyPhase);
        Assert.NotNull(runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial);
        Assert.NotNull(runtime.TlsState.RetainedOldOneRttProtectPacketProtectionMaterial);
        Assert.Null(runtime.TlsState.RetainedOldOneRttPacketProtectionDiscardAtMicros);
    }

    private static void SeedPhaseThreeTrackedPackets(QuicConnectionRuntime runtime)
    {
        QuicRfc9001KeyUpdateRetentionTestSupport.SeedTrackedOneRttPacket(
            runtime,
            packetNumber: 50,
            sentAtMicros: 500,
            keyPhase: 2);
        QuicRfc9001KeyUpdateRetentionTestSupport.SeedLostOneRttPacket(
            runtime,
            packetNumber: 51,
            sentAtMicros: 510,
            keyPhase: 2);
        QuicRfc9001KeyUpdateRetentionTestSupport.SeedTrackedOneRttPacket(
            runtime,
            packetNumber: 52,
            sentAtMicros: 520,
            keyPhase: 3);
    }

    private static void SeedPhaseFourTrackedPackets(QuicConnectionRuntime runtime)
    {
        QuicRfc9001KeyUpdateRetentionTestSupport.SeedTrackedOneRttPacket(
            runtime,
            packetNumber: 70,
            sentAtMicros: 700,
            keyPhase: 3);
        QuicRfc9001KeyUpdateRetentionTestSupport.SeedLostOneRttPacket(
            runtime,
            packetNumber: 71,
            sentAtMicros: 710,
            keyPhase: 3);
        QuicRfc9001KeyUpdateRetentionTestSupport.SeedTrackedOneRttPacket(
            runtime,
            packetNumber: 72,
            sentAtMicros: 720,
            keyPhase: 4);
    }

    private static void SeedPhaseFiveTrackedPackets(QuicConnectionRuntime runtime)
    {
        QuicRfc9001KeyUpdateRetentionTestSupport.SeedTrackedOneRttPacket(
            runtime,
            packetNumber: 90,
            sentAtMicros: 900,
            keyPhase: 4);
        QuicRfc9001KeyUpdateRetentionTestSupport.SeedLostOneRttPacket(
            runtime,
            packetNumber: 91,
            sentAtMicros: 910,
            keyPhase: 4);
        QuicRfc9001KeyUpdateRetentionTestSupport.SeedTrackedOneRttPacket(
            runtime,
            packetNumber: 92,
            sentAtMicros: 920,
            keyPhase: 5);
    }

    private static void SeedRepeatedPhaseTrackedPackets(QuicConnectionRuntime runtime)
    {
        QuicRfc9001KeyUpdateRetentionTestSupport.SeedTrackedOneRttPacket(
            runtime,
            packetNumber: 30,
            sentAtMicros: 300,
            keyPhase: 1);
        QuicRfc9001KeyUpdateRetentionTestSupport.SeedLostOneRttPacket(
            runtime,
            packetNumber: 31,
            sentAtMicros: 310,
            keyPhase: 1);
        QuicRfc9001KeyUpdateRetentionTestSupport.SeedTrackedOneRttPacket(
            runtime,
            packetNumber: 32,
            sentAtMicros: 320,
            keyPhase: 2);
    }

    private static void AssertRepeatedPhaseTwoDiscardedAndPhaseThreeRetained(
        QuicConnectionRuntime runtime,
        QuicConnectionTransitionResult timerResult)
    {
        QuicRecoveryController recoveryController =
            QuicRfc9001KeyUpdateRetentionTestSupport.GetRecoveryController(runtime);

        Assert.True(timerResult.StateChanged);
        Assert.Null(runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial);
        Assert.Null(runtime.TlsState.RetainedOldOneRttProtectPacketProtectionMaterial);
        Assert.True(runtime.TlsState.OneRttOpenPacketProtectionMaterial.HasValue);
        Assert.True(runtime.TlsState.OneRttProtectPacketProtectionMaterial.HasValue);
        Assert.DoesNotContain(runtime.SendRuntime.SentPackets.Values, packet => packet.OneRttKeyPhase == 2);
        Assert.Contains(runtime.SendRuntime.SentPackets.Values, packet => packet.OneRttKeyPhase == 3);
        Assert.Equal(0, runtime.SendRuntime.PendingRetransmissionCount);
        Assert.True(recoveryController.TrySelectLossDetectionTimer(
            nowMicros: 2_000,
            maxAckDelayMicros: 25_000,
            handshakeConfirmed: true,
            serverAtAntiAmplificationLimit: false,
            peerAddressValidationComplete: true,
            handshakeKeysAvailable: true,
            out _,
            out QuicPacketNumberSpace selectedPacketNumberSpace));
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, selectedPacketNumberSpace);
    }

    private static void AssertRepeatedPhaseThreeDiscardedAndPhaseFourRetained(
        QuicConnectionRuntime runtime,
        QuicConnectionTransitionResult timerResult)
    {
        QuicRecoveryController recoveryController =
            QuicRfc9001KeyUpdateRetentionTestSupport.GetRecoveryController(runtime);

        Assert.True(timerResult.StateChanged);
        Assert.Null(runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial);
        Assert.Null(runtime.TlsState.RetainedOldOneRttProtectPacketProtectionMaterial);
        Assert.True(runtime.TlsState.OneRttOpenPacketProtectionMaterial.HasValue);
        Assert.True(runtime.TlsState.OneRttProtectPacketProtectionMaterial.HasValue);
        Assert.DoesNotContain(runtime.SendRuntime.SentPackets.Values, packet => packet.OneRttKeyPhase == 3);
        Assert.Contains(runtime.SendRuntime.SentPackets.Values, packet => packet.OneRttKeyPhase == 4);
        Assert.Equal(0, runtime.SendRuntime.PendingRetransmissionCount);
        Assert.True(recoveryController.TrySelectLossDetectionTimer(
            nowMicros: 3_000,
            maxAckDelayMicros: 25_000,
            handshakeConfirmed: true,
            serverAtAntiAmplificationLimit: false,
            peerAddressValidationComplete: true,
            handshakeKeysAvailable: true,
            out _,
            out QuicPacketNumberSpace selectedPacketNumberSpace));
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, selectedPacketNumberSpace);
    }

    private static void AssertRepeatedPhaseFourDiscardedAndPhaseFiveRetained(
        QuicConnectionRuntime runtime,
        QuicConnectionTransitionResult timerResult)
    {
        QuicRecoveryController recoveryController =
            QuicRfc9001KeyUpdateRetentionTestSupport.GetRecoveryController(runtime);

        Assert.True(timerResult.StateChanged);
        Assert.Null(runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial);
        Assert.Null(runtime.TlsState.RetainedOldOneRttProtectPacketProtectionMaterial);
        Assert.True(runtime.TlsState.OneRttOpenPacketProtectionMaterial.HasValue);
        Assert.True(runtime.TlsState.OneRttProtectPacketProtectionMaterial.HasValue);
        Assert.DoesNotContain(runtime.SendRuntime.SentPackets.Values, packet => packet.OneRttKeyPhase == 4);
        Assert.Contains(runtime.SendRuntime.SentPackets.Values, packet => packet.OneRttKeyPhase == 5);
        Assert.Equal(0, runtime.SendRuntime.PendingRetransmissionCount);
        Assert.True(recoveryController.TrySelectLossDetectionTimer(
            nowMicros: 4_000,
            maxAckDelayMicros: 25_000,
            handshakeConfirmed: true,
            serverAtAntiAmplificationLimit: false,
            peerAddressValidationComplete: true,
            handshakeKeysAvailable: true,
            out _,
            out QuicPacketNumberSpace selectedPacketNumberSpace));
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, selectedPacketNumberSpace);
    }

    private static void AssertRepeatedPhaseOneDiscardedAndPhaseTwoRetained(
        QuicConnectionRuntime runtime,
        QuicConnectionTransitionResult timerResult)
    {
        QuicRecoveryController recoveryController =
            QuicRfc9001KeyUpdateRetentionTestSupport.GetRecoveryController(runtime);

        Assert.True(timerResult.StateChanged);
        Assert.Null(runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial);
        Assert.Null(runtime.TlsState.RetainedOldOneRttProtectPacketProtectionMaterial);
        Assert.True(runtime.TlsState.OneRttOpenPacketProtectionMaterial.HasValue);
        Assert.True(runtime.TlsState.OneRttProtectPacketProtectionMaterial.HasValue);
        Assert.DoesNotContain(runtime.SendRuntime.SentPackets.Values, packet => packet.OneRttKeyPhase == 1);
        Assert.Contains(runtime.SendRuntime.SentPackets.Values, packet => packet.OneRttKeyPhase == 2);
        Assert.Equal(0, runtime.SendRuntime.PendingRetransmissionCount);
        Assert.True(recoveryController.TrySelectLossDetectionTimer(
            nowMicros: 1_000,
            maxAckDelayMicros: 25_000,
            handshakeConfirmed: true,
            serverAtAntiAmplificationLimit: false,
            peerAddressValidationComplete: true,
            handshakeKeysAvailable: true,
            out _,
            out QuicPacketNumberSpace selectedPacketNumberSpace));
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, selectedPacketNumberSpace);
    }
}
