// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class QuicConnectionSendRuntimePacketOwnershipTests
{
    [Fact]
    public void ReserveSentPacket_ConsumesCapacityWithoutExposingPacketAsSent()
    {
        QuicConnectionSendRuntime runtime = new();
        ulong congestionWindow = runtime.FlowController.CongestionControlState.CongestionWindowBytes;

        Assert.True(runtime.TryReserveSentPacket(
            CreatePacket(packetNumber: 7, payloadBytes: congestionWindow),
            out QuicConnectionPendingSendReservation reservation));

        Assert.NotEqual(default, reservation);
        Assert.Empty(runtime.SentPackets);
        Assert.Equal(0UL, runtime.FlowController.CongestionControlState.BytesInFlightBytes);
        Assert.Equal(congestionWindow, runtime.FlowController.CongestionControlState.ReservedSendBytes);
        Assert.False(runtime.FlowController.CanSend(
            QuicPacketNumberSpace.ApplicationData,
            sentBytes: 1));
        Assert.False(runtime.TryAcknowledgePacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 7,
            handshakeConfirmed: true));
        Assert.False(runtime.TryReserveSentPacket(
            CreatePacket(packetNumber: 8, payloadBytes: 1),
            out QuicConnectionPendingSendReservation secondReservation));
        Assert.Equal(default, secondReservation);

        Assert.True(runtime.TryReleaseReservedSentPacket(reservation));
        Assert.Equal(0UL, runtime.FlowController.CongestionControlState.ReservedSendBytes);
        Assert.True(runtime.FlowController.CanSend(
            QuicPacketNumberSpace.ApplicationData,
            sentBytes: congestionWindow));
    }

    [Fact]
    public void CommitReservedSentPacket_ConvertsReservationWithoutDoubleCharging()
    {
        QuicConnectionSendRuntime runtime = new();
        Assert.True(runtime.TryReserveSentPacket(
            CreatePacket(packetNumber: 7, payloadBytes: 1_200, sentAtMicros: 100),
            out QuicConnectionPendingSendReservation reservation));

        Assert.NotEqual(default, reservation);
        Assert.True(runtime.TryCommitReservedSentPacket(reservation, sentAtMicros: 900));

        QuicConnectionSentPacket packet = Assert.Single(runtime.SentPackets).Value;
        Assert.Equal(900UL, packet.SentAtMicros);
        Assert.Equal(0UL, runtime.FlowController.CongestionControlState.ReservedSendBytes);
        Assert.Equal(1_200UL, runtime.FlowController.CongestionControlState.BytesInFlightBytes);
        Assert.False(runtime.TryCommitReservedSentPacket(reservation, sentAtMicros: 901));
        Assert.False(runtime.TryReleaseReservedSentPacket(reservation));
        Assert.Single(runtime.SentPackets);
        Assert.Equal(1_200UL, runtime.FlowController.CongestionControlState.BytesInFlightBytes);
    }

    [Fact]
    public void ResetInvalidatesReservedPacketAccountingBeforeCommit()
    {
        QuicConnectionSendRuntime runtime = new();
        Assert.True(runtime.TryReserveSentPacket(
            CreatePacket(packetNumber: 7, payloadBytes: 1_200),
            out QuicConnectionPendingSendReservation reservation));

        Assert.NotEqual(default, reservation);
        runtime.ResetPathRecoveryState();

        Assert.Equal(0UL, runtime.FlowController.CongestionControlState.ReservedSendBytes);
        Assert.False(runtime.TryCommitReservedSentPacket(reservation, sentAtMicros: 900));
        Assert.Empty(runtime.SentPackets);
        Assert.Equal(0UL, runtime.FlowController.CongestionControlState.BytesInFlightBytes);
    }

    [Fact]
    public void AckOnlyReservation_DoesNotConsumeCongestionCapacity()
    {
        QuicConnectionSendRuntime runtime = new();
        QuicConnectionSentPacket packet = CreatePacket(packetNumber: 7, payloadBytes: 64) with
        {
            AckEliciting = false,
            AckOnlyPacket = true,
            Retransmittable = false,
        };

        Assert.True(runtime.TryReserveSentPacket(
            packet,
            out QuicConnectionPendingSendReservation reservation));
        Assert.NotEqual(default, reservation);
        Assert.Equal(0UL, runtime.FlowController.CongestionControlState.ReservedSendBytes);

        Assert.True(runtime.TryCommitReservedSentPacket(reservation, sentAtMicros: 900));
        Assert.Empty(runtime.SentPackets);
        Assert.Equal(0UL, runtime.FlowController.CongestionControlState.BytesInFlightBytes);
    }

    [Fact]
    public void StorageSnapshotReportsCapacityOccupancyAndPerSpaceSpan()
    {
        QuicConnectionSendRuntime runtime = new();
        runtime.TrackSentPacket(new QuicConnectionSentPacket(QuicPacketNumberSpace.Initial, 5, 1, 10));
        runtime.TrackSentPacket(new QuicConnectionSentPacket(QuicPacketNumberSpace.Initial, 9, 1, 11));
        runtime.TrackSentPacket(new QuicConnectionSentPacket(QuicPacketNumberSpace.Handshake, 10, 1, 12));
        runtime.TrackSentPacket(new QuicConnectionSentPacket(QuicPacketNumberSpace.ApplicationData, 100, 1, 13));
        runtime.TrackSentPacket(new QuicConnectionSentPacket(QuicPacketNumberSpace.ApplicationData, 103, 1, 14));

        QuicSentPacketStorageSnapshot storageOnlySnapshot = runtime.CaptureSentPacketStorageSnapshot();
        _ = runtime.CaptureSentPacketRetentionSnapshot(20, out QuicSentPacketStorageSnapshot snapshot);

        Assert.Equal(snapshot, storageOnlySnapshot);
        Assert.Equal(5, snapshot.RetainedPacketCount);
        Assert.True(snapshot.Capacity >= 64);
        Assert.Equal(new QuicSentPacketNumberSpaceStorageSnapshot(2, 5), snapshot.Initial);
        Assert.Equal(new QuicSentPacketNumberSpaceStorageSnapshot(1, 1), snapshot.Handshake);
        Assert.Equal(new QuicSentPacketNumberSpaceStorageSnapshot(2, 4), snapshot.ApplicationData);
    }

    [Fact]
    public void HostedSendCanDetachLatestRebuildableProtectedPacketOwner()
    {
        QuicConnectionSendRuntime runtime = new();
        byte[] plaintextOwner = QuicBufferPool.RentBytes(3);
        byte[] packetOwner = QuicBufferPool.RentBytes(17);
        ReadOnlyMemory<byte> packetBytes = packetOwner.AsMemory(0, 17);
        QuicConnectionSentPacketKey key = new(QuicPacketNumberSpace.ApplicationData, 7);

        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 7,
            PayloadBytes: 17,
            SentAtMicros: 100,
            PacketProtectionLevel: QuicTlsEncryptionLevel.OneRtt,
            PacketBytes: packetBytes,
            PlaintextPayload: plaintextOwner.AsMemory(0, 3),
            PlaintextPayloadOwner: plaintextOwner,
            PacketBytesOwner: packetOwner));

        Assert.True(runtime.TryDetachLatestRebuildablePacketBytes(packetBytes, out byte[]? detachedOwner));
        Assert.Same(packetOwner, detachedOwner);
        Assert.True(runtime.SentPackets[key].PacketBytes.IsEmpty);
        Assert.Null(runtime.SentPackets[key].PacketBytesOwner);
        Assert.Same(plaintextOwner, runtime.SentPackets[key].PlaintextPayloadOwner);

        QuicBufferPool.ReturnBytes(detachedOwner);
        Assert.True(runtime.TryDiscardPacketNumberSpace(QuicPacketNumberSpace.ApplicationData));
    }

    [Fact]
    public void HostedSendDoesNotDetachWhenPlaintextAliasesProtectedPacketOwner()
    {
        QuicConnectionSendRuntime runtime = new();
        byte[] sharedOwner = new byte[32];
        ReadOnlyMemory<byte> packetBytes = sharedOwner.AsMemory(0, 17);

        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 7,
            PayloadBytes: 17,
            SentAtMicros: 100,
            PacketProtectionLevel: QuicTlsEncryptionLevel.OneRtt,
            PacketBytes: packetBytes,
            PlaintextPayload: sharedOwner.AsMemory(17, 3),
            PlaintextPayloadOwner: sharedOwner,
            PacketBytesOwner: sharedOwner));

        Assert.False(runtime.TryDetachLatestRebuildablePacketBytes(packetBytes, out byte[]? detachedOwner));
        Assert.Null(detachedOwner);
        Assert.Same(sharedOwner, runtime.SentPackets.Single().Value.PacketBytesOwner);
    }

    [Fact]
    public void RetentionSnapshotHelpersDeduplicateAliasedOwnersAndClampClockSkew()
    {
        byte[] owner = new byte[32];
        long retainedBufferCount = 0;
        long retainedByteCount = 0;

        QuicRetentionSnapshot.AddOwners(
            owner,
            owner,
            ref retainedBufferCount,
            ref retainedByteCount);

        Assert.Equal(1, retainedBufferCount);
        Assert.Equal(owner.Length, retainedByteCount);
        Assert.Equal(0, QuicRetentionSnapshot.GetOldestAgeMilliseconds(
            nowMicros: 500,
            oldestSentAtMicros: 1_000));
    }

    [Fact]
    public void RetentionSnapshotsCountOwnersBytesAndOldestAge()
    {
        QuicConnectionSendRuntime runtime = new();
        byte[] sentPlaintextOwner = QuicBufferPool.RentBytes(3);
        byte[] sentPacketOwner = QuicBufferPool.RentBytes(17);
        byte[] retransmissionOwner = QuicBufferPool.RentBytes(5);

        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 1,
            PayloadBytes: 17,
            SentAtMicros: 500,
            PacketProtectionLevel: QuicTlsEncryptionLevel.OneRtt,
            PlaintextPayload: sentPlaintextOwner.AsMemory(0, 3),
            PlaintextPayloadOwner: sentPlaintextOwner,
            PacketBytes: sentPacketOwner.AsMemory(0, 17),
            PacketBytesOwner: sentPacketOwner));
        runtime.QueueRetransmission(new QuicConnectionRetransmissionPlan(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 2,
            PayloadBytes: 5,
            SentAtMicros: 1_000,
            PacketProtectionLevel: QuicTlsEncryptionLevel.OneRtt,
            PlaintextPayload: retransmissionOwner.AsMemory(0, 5),
            PlaintextPayloadOwner: retransmissionOwner));

        QuicRetentionSnapshot sent = runtime.CaptureSentPacketRetentionSnapshot(nowMicros: 2_500);
        QuicRetentionSnapshot retransmission = runtime.CaptureRetransmissionRetentionSnapshot(nowMicros: 3_000);

        Assert.Equal(2, sent.RetainedBufferCount);
        Assert.Equal(sentPlaintextOwner.Length + sentPacketOwner.Length, sent.RetainedByteCount);
        Assert.Equal(2.0, sent.OldestAgeMilliseconds);
        Assert.Equal(1, retransmission.RetainedBufferCount);
        Assert.Equal(retransmissionOwner.Length, retransmission.RetainedByteCount);
        Assert.Equal(2.0, retransmission.OldestAgeMilliseconds);

        Assert.True(runtime.TryDiscardPacketNumberSpace(QuicPacketNumberSpace.ApplicationData));
    }

    [Fact]
    public void TrackAndAcknowledgePacket_UsesAuthoritativeLedgerForCongestionState()
    {
        QuicConnectionSendRuntime runtime = new();
        runtime.TrackSentPacket(CreatePacket(packetNumber: 7, payloadBytes: 1_200));

        Assert.Single(runtime.SentPackets);
        Assert.Equal(0, runtime.FlowController.RetainedSentPacketStateCount);
        Assert.Equal(1_200UL, runtime.FlowController.CongestionControlState.BytesInFlightBytes);

        using QuicAckFrame ackFrame = QuicS19P3AckFrameTestSupport.CreateSinglePacketAckFrame(7);
        QuicConnectionSentPacket packet = Assert.Single(runtime.SentPackets).Value;
        Assert.True(runtime.FlowController.TryRegisterExternallyRetainedAcknowledgment(packet, ackReceivedAtMicros: 200));
        _ = runtime.FlowController.TryFinalizeExternallyRetainedAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            ackFrame,
            ackReceivedAtMicros: 200,
            largestAcknowledgedPacketSentAtMicros: packet.SentAtMicros);
        Assert.True(runtime.TryAcknowledgePacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 7,
            handshakeConfirmed: true));

        Assert.Empty(runtime.SentPackets);
        Assert.Equal(0, runtime.FlowController.RetainedSentPacketStateCount);
        Assert.Equal(0UL, runtime.FlowController.CongestionControlState.BytesInFlightBytes);
    }

    [Fact]
    public void RegisterLoss_UsesAuthoritativeLedgerForCongestionState()
    {
        QuicConnectionSendRuntime runtime = new();
        runtime.TrackSentPacket(CreatePacket(packetNumber: 11, payloadBytes: 900));

        Assert.True(runtime.TryRegisterLoss(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 11,
            handshakeConfirmed: true,
            scheduleRetransmission: false));

        Assert.Empty(runtime.SentPackets);
        Assert.Equal(0, runtime.FlowController.RetainedSentPacketStateCount);
        Assert.Equal(0UL, runtime.FlowController.CongestionControlState.BytesInFlightBytes);
    }

    [Fact]
    public void ProcessDiscontiguousAcknowledgments_UsesAuthoritativeLedgerForEveryAcknowledgedPacket()
    {
        QuicConnectionSendRuntime runtime = new();
        runtime.TrackSentPacket(CreatePacket(packetNumber: 7, payloadBytes: 700, sentAtMicros: 100));
        runtime.TrackSentPacket(CreatePacket(packetNumber: 8, payloadBytes: 800, sentAtMicros: 200));
        runtime.TrackSentPacket(CreatePacket(packetNumber: 9, payloadBytes: 900, sentAtMicros: 300));
        Assert.True(runtime.TryRegisterLoss(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 8,
            handshakeConfirmed: true,
            scheduleRetransmission: false));
        Assert.Equal(200UL, runtime.FlowController.CongestionControlState.RecoveryStartTimeMicros);

        using QuicAckFrame ackFrame = QuicS19P3AckFrameTestSupport.CreateAckFrameWithAdditionalRange(
            largestAcknowledged: 9,
            firstAckRange: 0,
            gap: 0,
            ackRangeLength: 0);
        foreach (ulong packetNumber in new[] { 7UL, 9UL })
        {
            QuicConnectionSentPacketKey key = new(QuicPacketNumberSpace.ApplicationData, packetNumber);
            QuicConnectionSentPacket packet = runtime.SentPackets[key];
            Assert.True(runtime.FlowController.TryRegisterExternallyRetainedAcknowledgment(
                packet,
                ackReceivedAtMicros: 400,
                pacingLimited: true));
            if (packetNumber == 7)
            {
                Assert.Equal(200UL, runtime.FlowController.CongestionControlState.RecoveryStartTimeMicros);
            }

            Assert.True(runtime.TryAcknowledgePacket(
                QuicPacketNumberSpace.ApplicationData,
                packetNumber,
                handshakeConfirmed: true));
        }

        _ = runtime.FlowController.TryFinalizeExternallyRetainedAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            ackFrame,
            ackReceivedAtMicros: 400,
            largestAcknowledgedPacketSentAtMicros: 300);

        Assert.Empty(runtime.SentPackets);
        Assert.Null(runtime.FlowController.CongestionControlState.RecoveryStartTimeMicros);
        Assert.Equal(0UL, runtime.FlowController.CongestionControlState.BytesInFlightBytes);
        Assert.Equal(0, runtime.FlowController.RetainedSentPacketStateCount);
    }

    [Fact]
    public void DiscardKeyPhaseAndProtectionLevel_UseAuthoritativeLedgerForCongestionState()
    {
        QuicConnectionSendRuntime runtime = new();
        runtime.TrackSentPacket(CreatePacket(packetNumber: 7, payloadBytes: 700, oneRttKeyPhase: 0));
        runtime.TrackSentPacket(CreatePacket(packetNumber: 8, payloadBytes: 800, oneRttKeyPhase: 1));

        Assert.True(runtime.TryDiscardOneRttKeyPhase(0));
        Assert.Single(runtime.SentPackets);
        Assert.Equal(800UL, runtime.FlowController.CongestionControlState.BytesInFlightBytes);
        Assert.Equal(0, runtime.FlowController.RetainedSentPacketStateCount);

        Assert.True(runtime.TryDiscardPacketProtectionLevel(QuicTlsEncryptionLevel.OneRtt));
        Assert.Empty(runtime.SentPackets);
        Assert.Equal(0UL, runtime.FlowController.CongestionControlState.BytesInFlightBytes);
        Assert.Equal(0, runtime.FlowController.RetainedSentPacketStateCount);
    }

    [Fact]
    public void PathMigrationRequeuesOwnedPlaintextWithoutAliasingDiscardedOwners()
    {
        QuicConnectionSendRuntime runtime = new();
        byte[] sentOwner = QuicBufferPool.RentBytes(3);
        byte[] retransmissionOwner = QuicBufferPool.RentBytes(2);
        new byte[] { 0x11, 0x22, 0x33 }.CopyTo(sentOwner, 0);
        new byte[] { 0x44, 0x55 }.CopyTo(retransmissionOwner, 0);

        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 7,
            PayloadBytes: 3,
            SentAtMicros: 100,
            PacketProtectionLevel: QuicTlsEncryptionLevel.OneRtt,
            PacketBytes: sentOwner.AsMemory(0, 3),
            PlaintextPayload: sentOwner.AsMemory(0, 3),
            PacketBytesOwner: sentOwner));
        runtime.QueueRetransmission(new QuicConnectionRetransmissionPlan(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 8,
            PayloadBytes: 2,
            SentAtMicros: 200,
            PacketProtectionLevel: QuicTlsEncryptionLevel.OneRtt,
            PlaintextPayload: retransmissionOwner.AsMemory(0, 2),
            PlaintextPayloadOwner: retransmissionOwner));

        Assert.True(runtime.TryDiscardPacketNumberSpaceForPathMigration(
            QuicPacketNumberSpace.ApplicationData));
        Assert.Empty(runtime.SentPackets);
        Assert.Equal(2, runtime.PendingRetransmissionCount);

        Assert.True(runtime.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan sentPlan));
        Assert.NotNull(sentPlan.PlaintextPayloadOwner);
        Assert.NotSame(sentOwner, sentPlan.PlaintextPayloadOwner);
        Assert.Equal(new byte[] { 0x11, 0x22, 0x33 }, sentPlan.PlaintextPayload.ToArray());

        Assert.True(runtime.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan queuedPlan));
        Assert.NotNull(queuedPlan.PlaintextPayloadOwner);
        Assert.NotSame(retransmissionOwner, queuedPlan.PlaintextPayloadOwner);
        Assert.Equal(new byte[] { 0x44, 0x55 }, queuedPlan.PlaintextPayload.ToArray());

        QuicConnectionSendRuntime.ReleaseRetransmissionPlanResources(sentPlan);
        QuicConnectionSendRuntime.ReleaseRetransmissionPlanResources(queuedPlan);
    }

    private static QuicConnectionSentPacket CreatePacket(
        ulong packetNumber,
        ulong payloadBytes,
        ulong oneRttKeyPhase = 0,
        ulong sentAtMicros = 100)
        => new(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber,
            payloadBytes,
            SentAtMicros: sentAtMicros,
            AckEliciting: true,
            Retransmittable: true,
            PacketProtectionLevel: QuicTlsEncryptionLevel.OneRtt,
            OneRttKeyPhase: oneRttKeyPhase);
}
