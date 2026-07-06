// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9002-S6-4-P3-S1-R01">An endpoint MUST discard recovery state for all in-flight 0-RTT packets when 0-RTT is rejected.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9002-S6-4-P3-S1-R01")]
public sealed class RFC9002_S6_4_P3_S1_R01
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RejectingTheResumptionAttempt_DiscardsZeroRttRecoveryStateAndRetainsOneRttPackets()
    {
        QuicConnectionRuntime runtime = CreateRuntime();
        runtime.SendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 1,
            PayloadBytes: 1_200,
            SentAtMicros: 100,
            AckEliciting: true,
            Retransmittable: true,
            PacketBytes: new byte[] { 0x01 },
            PacketProtectionLevel: QuicTlsEncryptionLevel.ZeroRtt));
        runtime.SendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 2,
            PayloadBytes: 1_200,
            SentAtMicros: 200,
            AckEliciting: true,
            Retransmittable: true,
            PacketBytes: new byte[] { 0x02 },
            PacketProtectionLevel: QuicTlsEncryptionLevel.ZeroRtt));
        runtime.SendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 3,
            PayloadBytes: 1_200,
            SentAtMicros: 300,
            AckEliciting: true,
            PacketBytes: new byte[] { 0x03 },
            PacketProtectionLevel: QuicTlsEncryptionLevel.OneRtt));

        Assert.True(runtime.SendRuntime.TryRegisterLoss(
            QuicPacketNumberSpace.ApplicationData,
            2,
            handshakeConfirmed: false));
        Assert.Equal(2, runtime.SendRuntime.SentPackets.Count);
        Assert.Equal(1, runtime.SendRuntime.PendingRetransmissionCount);
        Assert.Equal(2_400UL, runtime.SendRuntime.FlowController.CongestionControlState.BytesInFlightBytes);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 1,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.ResumptionAttemptDispositionAvailable,
                    ResumptionAttemptDisposition: QuicTlsResumptionAttemptDisposition.Rejected)),
            nowTicks: 1);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicTlsResumptionAttemptDisposition.Rejected, runtime.TlsState.ResumptionAttemptDisposition);
        Assert.True(runtime.TlsState.OldKeysDiscarded);
        Assert.DoesNotContain(
            runtime.SendRuntime.SentPackets.Values,
            packet => packet.PacketProtectionLevel == QuicTlsEncryptionLevel.ZeroRtt);
        Assert.Contains(
            runtime.SendRuntime.SentPackets.Values,
            packet => packet.PacketProtectionLevel == QuicTlsEncryptionLevel.OneRtt);
        Assert.Equal(0, runtime.SendRuntime.PendingRetransmissionCount);
        Assert.Equal(1_200UL, runtime.SendRuntime.FlowController.CongestionControlState.BytesInFlightBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AcceptingTheResumptionAttempt_KeepsZeroRttRecoveryStateIntact()
    {
        QuicConnectionRuntime runtime = CreateRuntime();
        runtime.SendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 1,
            PayloadBytes: 1_200,
            SentAtMicros: 100,
            AckEliciting: true,
            Retransmittable: true,
            PacketBytes: new byte[] { 0x01 },
            PacketProtectionLevel: QuicTlsEncryptionLevel.ZeroRtt));
        runtime.SendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 2,
            PayloadBytes: 1_200,
            SentAtMicros: 200,
            AckEliciting: true,
            Retransmittable: true,
            PacketBytes: new byte[] { 0x02 },
            PacketProtectionLevel: QuicTlsEncryptionLevel.ZeroRtt));
        runtime.SendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 3,
            PayloadBytes: 1_200,
            SentAtMicros: 300,
            AckEliciting: true,
            PacketBytes: new byte[] { 0x03 },
            PacketProtectionLevel: QuicTlsEncryptionLevel.OneRtt));

        Assert.True(runtime.SendRuntime.TryRegisterLoss(
            QuicPacketNumberSpace.ApplicationData,
            2,
            handshakeConfirmed: false));

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 1,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.ResumptionAttemptDispositionAvailable,
                    ResumptionAttemptDisposition: QuicTlsResumptionAttemptDisposition.Accepted)),
            nowTicks: 1);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicTlsResumptionAttemptDisposition.Accepted, runtime.TlsState.ResumptionAttemptDisposition);
        Assert.False(runtime.TlsState.OldKeysDiscarded);
        Assert.Contains(
            runtime.SendRuntime.SentPackets.Values,
            packet => packet.PacketProtectionLevel == QuicTlsEncryptionLevel.ZeroRtt);
        Assert.Equal(1, runtime.SendRuntime.PendingRetransmissionCount);
        Assert.Equal(2_400UL, runtime.SendRuntime.FlowController.CongestionControlState.BytesInFlightBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RejectingResumption_DiscardsAllZeroRttRecoveryStateAndRetainsOneRttPackets()
    {
        foreach ((int zeroRttPacketCount, int oneRttPacketCount, int lostZeroRttIndex) in new (int, int, int)[]
        {
            (2, 1, 0),
            (3, 2, 1),
            (5, 3, 4),
        })
        {
            QuicConnectionRuntime runtime = CreateRuntime();
            ulong expectedOneRttBytesInFlight = 0;
            ulong expectedZeroRttBytesAfterLoss = 0;

            for (int i = 0; i < zeroRttPacketCount; i++)
            {
                ulong payloadBytes = 900UL + (ulong)(i * 73);
                runtime.SendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
                    QuicPacketNumberSpace.ApplicationData,
                    PacketNumber: (ulong)(i + 1),
                    PayloadBytes: payloadBytes,
                    SentAtMicros: (ulong)(100 + i),
                    AckEliciting: true,
                    Retransmittable: true,
                    PacketBytes: new byte[] { (byte)(0x10 + i) },
                    PacketProtectionLevel: QuicTlsEncryptionLevel.ZeroRtt));

                if (i != lostZeroRttIndex)
                {
                    expectedZeroRttBytesAfterLoss += payloadBytes;
                }
            }

            for (int i = 0; i < oneRttPacketCount; i++)
            {
                ulong payloadBytes = 700UL + (ulong)(i * 41);
                runtime.SendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
                    QuicPacketNumberSpace.ApplicationData,
                    PacketNumber: (ulong)(100 + i),
                    PayloadBytes: payloadBytes,
                    SentAtMicros: (ulong)(200 + i),
                    AckEliciting: true,
                    Retransmittable: true,
                    PacketBytes: new byte[] { (byte)(0x80 + i) },
                    PacketProtectionLevel: QuicTlsEncryptionLevel.OneRtt));
                expectedOneRttBytesInFlight += payloadBytes;
            }

            Assert.True(runtime.SendRuntime.TryRegisterLoss(
                QuicPacketNumberSpace.ApplicationData,
                (ulong)(lostZeroRttIndex + 1),
                handshakeConfirmed: false));
            Assert.Equal(1, runtime.SendRuntime.PendingRetransmissionCount);
            Assert.Equal(
                expectedZeroRttBytesAfterLoss + expectedOneRttBytesInFlight,
                runtime.SendRuntime.FlowController.CongestionControlState.BytesInFlightBytes);

            QuicConnectionTransitionResult result = runtime.Transition(
                new QuicConnectionTlsStateUpdatedEvent(
                    ObservedAtTicks: 1,
                    new QuicTlsStateUpdate(
                        QuicTlsUpdateKind.ResumptionAttemptDispositionAvailable,
                        ResumptionAttemptDisposition: QuicTlsResumptionAttemptDisposition.Rejected)),
                nowTicks: 1);

            Assert.True(result.StateChanged);
            Assert.Equal(QuicTlsResumptionAttemptDisposition.Rejected, runtime.TlsState.ResumptionAttemptDisposition);
            Assert.DoesNotContain(
                runtime.SendRuntime.SentPackets.Values,
                packet => packet.PacketProtectionLevel == QuicTlsEncryptionLevel.ZeroRtt);
            Assert.Equal(
                oneRttPacketCount,
                runtime.SendRuntime.SentPackets.Values.Count(packet => packet.PacketProtectionLevel == QuicTlsEncryptionLevel.OneRtt));
            Assert.Equal(0, runtime.SendRuntime.PendingRetransmissionCount);
            Assert.Equal(
                expectedOneRttBytesInFlight,
                runtime.SendRuntime.FlowController.CongestionControlState.BytesInFlightBytes);
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryDiscardPacketProtectionLevel_RemovesZeroRttPacketsWhileRetainingOneRttPackets()
    {
        QuicRecoveryController controller = new();
        controller.RecordPacketSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 1,
            sentAtMicros: 100,
            isAckElicitingPacket: true,
            packetProtectionLevel: QuicTlsEncryptionLevel.ZeroRtt);
        controller.RecordPacketSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 2,
            sentAtMicros: 200,
            isAckElicitingPacket: true,
            packetProtectionLevel: QuicTlsEncryptionLevel.OneRtt);

        Assert.True(controller.TrySelectLossDetectionTimer(
            nowMicros: 300,
            maxAckDelayMicros: 25_000,
            handshakeConfirmed: true,
            serverAtAntiAmplificationLimit: false,
            peerAddressValidationComplete: true,
            handshakeKeysAvailable: true,
            out ulong selectedRecoveryTimerMicros,
            out QuicPacketNumberSpace selectedPacketNumberSpace));
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, selectedPacketNumberSpace);
        Assert.NotEqual(0UL, selectedRecoveryTimerMicros);

        Assert.True(controller.TryDiscardPacketProtectionLevel(QuicTlsEncryptionLevel.ZeroRtt));
        Assert.True(controller.TrySelectLossDetectionTimer(
            nowMicros: 400,
            maxAckDelayMicros: 25_000,
            handshakeConfirmed: true,
            serverAtAntiAmplificationLimit: false,
            peerAddressValidationComplete: true,
            handshakeKeysAvailable: true,
            out selectedRecoveryTimerMicros,
            out selectedPacketNumberSpace));
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, selectedPacketNumberSpace);
        Assert.NotEqual(0UL, selectedRecoveryTimerMicros);

        Assert.True(controller.TryDiscardPacketProtectionLevel(QuicTlsEncryptionLevel.OneRtt));
        Assert.False(controller.TrySelectLossDetectionTimer(
            nowMicros: 500,
            maxAckDelayMicros: 25_000,
            handshakeConfirmed: true,
            serverAtAntiAmplificationLimit: false,
            peerAddressValidationComplete: true,
            handshakeKeysAvailable: true,
            out _,
            out _));
    }

    private static QuicConnectionRuntime CreateRuntime()
    {
        return new QuicConnectionRuntime(QuicConnectionStreamStateTestHelpers.CreateState());
    }
}
