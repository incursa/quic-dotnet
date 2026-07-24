// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Runtime.CompilerServices;

namespace Incursa.Quic.Tests;

public sealed class QuicConnectionRuntimeShardWorkItemLayoutTests
{
    [Fact]
    public void LayoutRemainsCompact()
    {
        Assert.Equal(144, Unsafe.SizeOf<QuicConnectionRuntimeShardWorkItem>());
    }

    [Theory]
    [InlineData(1UL, 0UL, 0UL)]
    [InlineData(0UL, 1UL, 0UL)]
    [InlineData(0UL, 0UL, 1UL)]
    public void PacketVariantRoundTripsCompactEcnCounts(
        ulong ect0Count,
        ulong ect1Count,
        ulong ecnCeCount)
    {
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicEcnCounts ecnCounts = new(ect0Count, ect1Count, ecnCeCount);
        QuicConnectionPacketReceivedContext packet = new(
            1,
            new QuicConnectionPathIdentity("remote"),
            new byte[] { 1 },
            EcnCounts: ecnCounts);
        QuicConnectionRuntimeShardWorkItem item = new(
            new QuicConnectionHandle(6),
            runtime,
            packet,
            ownedDatagramBuffer: null,
            ownedDatagramBufferOwnership: default);

        Assert.Equal(ecnCounts.Ect0Count, item.PacketReceived.EcnCounts?.Ect0Count);
        Assert.Equal(ecnCounts.Ect1Count, item.PacketReceived.EcnCounts?.Ect1Count);
        Assert.Equal(ecnCounts.EcnCeCount, item.PacketReceived.EcnCounts?.EcnCeCount);
    }

    [Fact]
    public void PacketVariantPreservesNullEcnCounts()
    {
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionPacketReceivedContext packet = new(
            1,
            new QuicConnectionPathIdentity("remote"),
            new byte[] { 1 });
        QuicConnectionRuntimeShardWorkItem item = new(
            new QuicConnectionHandle(6),
            runtime,
            packet,
            ownedDatagramBuffer: null,
            ownedDatagramBufferOwnership: default);

        Assert.Null(item.PacketReceived.EcnCounts);
        Assert.Null(item.OwnedDatagramBuffer);
    }

    [Fact]
    public void EventVariantPreservesReferenceAndDefaultsInactivePayloads()
    {
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionTimerExpiredEvent connectionEvent = new(7, QuicConnectionTimerKind.IdleTimeout, 9);
        QuicConnectionRuntimeShardWorkItem item = new(new QuicConnectionHandle(5), runtime, connectionEvent);

        Assert.Equal(QuicConnectionRuntimeShardWorkItemKind.Event, item.Kind);
        Assert.Same(connectionEvent, item.ConnectionEvent);
        Assert.Equal(default, item.PacketReceived);
        Assert.Null(item.OwnedDatagramBuffer);
        Assert.Equal(0, item.RequestId);
        Assert.True(item.StreamData.IsEmpty);
        Assert.True(item.StreamDataSuffix.IsEmpty);
        Assert.Null(item.ScheduledDueTicks);
    }

    [Fact]
    public void TimerVariantUsesExistingStorageForScheduledDeadline()
    {
        using QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionTimerExpiredEvent connectionEvent = new(
            7,
            QuicConnectionTimerKind.ApplicationSendDelay,
            9);
        QuicConnectionRuntimeShardWorkItem item = new(
            new QuicConnectionHandle(5),
            runtime,
            connectionEvent,
            scheduledDueTicks: long.MinValue);

        Assert.Equal(144, Unsafe.SizeOf<QuicConnectionRuntimeShardWorkItem>());
        Assert.Same(connectionEvent, item.ConnectionEvent);
        Assert.Equal(long.MinValue, item.ScheduledDueTicks);
        Assert.Equal(0, item.RequestId);
    }

    [Fact]
    public void ActorServiceContenderTrackingUsesExistingFlagStorage()
    {
        using QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionRuntimeShardWorkItem item = new(
            new QuicConnectionHandle(5),
            runtime,
            new QuicConnectionTimerExpiredEvent(
                7,
                QuicConnectionTimerKind.ApplicationSendDelay,
                9),
            scheduledDueTicks: long.MinValue);

        QuicConnectionRuntimeShardWorkItem tracked =
            item.WithActorServiceContenderTrackingAccepted();

        Assert.Equal(144, Unsafe.SizeOf<QuicConnectionRuntimeShardWorkItem>());
        Assert.False(item.ActorServiceContenderTrackingAccepted);
        Assert.True(tracked.ActorServiceContenderTrackingAccepted);
        Assert.Equal(long.MinValue, tracked.ScheduledDueTicks);
        Assert.Same(item.ConnectionEvent, tracked.ConnectionEvent);
    }

    [Fact]
    public void PacketVariantRoundTripsFullRangeNullableMetadataAndOwnership()
    {
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        byte[] datagram = [1, 2, 3];
        QuicConnectionPathIdentity pathIdentity = new("remote", "local", int.MinValue, int.MaxValue);
        QuicEcnCounts ecnCounts = new(ulong.MaxValue, ulong.MaxValue - 1, ulong.MaxValue - 2);
        QuicConnectionPacketReceivedContext packet = new(
            long.MinValue,
            pathIdentity,
            datagram,
            RoutedLocallyIssuedConnectionId: ulong.MaxValue,
            EcnCounts: ecnCounts);
        QuicReceiveBufferOwnership ownership = new(null, RingToken: 1);
        QuicConnectionRuntimeShardWorkItem item = new(
            new QuicConnectionHandle(6),
            runtime,
            packet,
            datagram,
            ownership);

        Assert.Equal(QuicConnectionRuntimeShardWorkItemKind.PacketReceived, item.Kind);
        Assert.Equal(packet, item.PacketReceived);
        Assert.True(item.PacketReceived.Datagram.Span.SequenceEqual(datagram));
        Assert.Same(datagram, item.OwnedDatagramBuffer);
        Assert.Equal(ownership, item.OwnedDatagramBufferOwnership);
        Assert.Null(item.ConnectionEvent);
        Assert.Equal(0, item.RequestId);
        Assert.True(item.StreamData.IsEmpty);
        Assert.True(item.StreamDataSuffix.IsEmpty);
    }

    [Fact]
    public void StreamVariantsShareStorageWithoutCrossKindLeakage()
    {
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionRuntimeShardWorkItem open = new(
            new QuicConnectionHandle(7),
            runtime,
            long.MinValue,
            (QuicStreamType)byte.MaxValue);
        byte[] streamData = [4, 5, 6];
        byte[] streamDataSuffix = [7, 8];
        QuicConnectionRuntimeShardWorkItem write = new QuicConnectionRuntimeShardWorkItem(
            new QuicConnectionHandle(8),
            runtime,
            long.MaxValue,
            QuicConnectionStreamActionKind.Write,
            ulong.MaxValue,
            streamData,
            streamDataSuffix) with
        {
            EnqueuedTimestamp = long.MaxValue - 1,
        };

        Assert.Equal(long.MinValue, open.RequestId);
        Assert.Equal((QuicStreamType)byte.MaxValue, open.StreamType);
        Assert.Equal(0UL, open.StreamId);
        Assert.True(open.StreamData.IsEmpty);
        Assert.Equal(long.MaxValue, write.RequestId);
        Assert.Equal(QuicConnectionStreamActionKind.Write, write.StreamActionKind);
        Assert.Equal(ulong.MaxValue, write.StreamId);
        Assert.True(write.StreamData.Span.SequenceEqual(streamData));
        Assert.True(write.StreamDataSuffix.Span.SequenceEqual(streamDataSuffix));
        Assert.Equal(long.MaxValue - 1, write.EnqueuedTimestamp);
        Assert.Equal(default, write.PacketReceived);
        Assert.Null(write.ConnectionEvent);
    }

    [Fact]
    public void AckFinalizationDeferralRequiresSameRuntimePacketOrStreamWrite()
    {
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        using QuicConnectionRuntime otherRuntime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionRuntimeShardWorkItem packet = CreatePacketWorkItem(runtime);
        QuicConnectionRuntimeShardWorkItem sameRuntimePacket = CreatePacketWorkItem(runtime);
        QuicConnectionRuntimeShardWorkItem otherRuntimePacket = CreatePacketWorkItem(otherRuntime);
        QuicConnectionRuntimeShardWorkItem streamWrite = new(
            new QuicConnectionHandle(8),
            runtime,
            requestId: 1,
            QuicConnectionStreamActionKind.Write,
            streamId: 0,
            new byte[] { 1 });
        QuicConnectionRuntimeShardWorkItem streamOpen = new(
            new QuicConnectionHandle(8),
            runtime,
            requestId: 2,
            QuicStreamType.Bidirectional);

        Assert.True(QuicConnectionRuntimeShard.ShouldDeferApplicationAckFinalization(
            in packet,
            in sameRuntimePacket,
            deferredPacketCount: 0,
            out bool finalizeAfterPacket));
        Assert.False(finalizeAfterPacket);

        Assert.True(QuicConnectionRuntimeShard.ShouldDeferApplicationAckFinalization(
            in packet,
            in streamWrite,
            deferredPacketCount: 7,
            out bool finalizeAfterWrite));
        Assert.True(finalizeAfterWrite);

        Assert.False(QuicConnectionRuntimeShard.ShouldDeferApplicationAckFinalization(
            in packet,
            in otherRuntimePacket,
            deferredPacketCount: 0,
            out _));
        Assert.False(QuicConnectionRuntimeShard.ShouldDeferApplicationAckFinalization(
            in packet,
            in streamOpen,
            deferredPacketCount: 0,
            out _));
        Assert.False(QuicConnectionRuntimeShard.ShouldDeferApplicationAckFinalization(
            in packet,
            in sameRuntimePacket,
            deferredPacketCount: 8,
            out _));
    }

    private static QuicConnectionRuntimeShardWorkItem CreatePacketWorkItem(QuicConnectionRuntime runtime)
    {
        QuicConnectionPacketReceivedContext packet = new(
            ObservedAtTicks: 1,
            new QuicConnectionPathIdentity("remote"),
            new byte[] { 1 });
        return new QuicConnectionRuntimeShardWorkItem(
            new QuicConnectionHandle(6),
            runtime,
            packet,
            ownedDatagramBuffer: null,
            ownedDatagramBufferOwnership: default);
    }
}
