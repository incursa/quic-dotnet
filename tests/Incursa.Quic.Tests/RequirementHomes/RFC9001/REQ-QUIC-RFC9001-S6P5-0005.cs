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
}
