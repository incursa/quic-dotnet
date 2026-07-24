// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text.Json;
using System.Text.Json.Serialization;

namespace Incursa.Quic.Tests.RequirementHomes.CRT;

[Requirement("REQ-QUIC-CRT-0182")]
public sealed class REQ_QUIC_CRT_0182
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ObserveOnlyCopyOperationsRemainLegacyAndAccumulate()
    {
        QuicBufferCopyEpochAccumulator accumulator = new();
        using QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState());
        runtime.ConfigureAdaptiveRuntimePolicy(new QuicServerConnectionOptions
        {
            BufferCopyObservationMode =
                QuicBufferCopyObservationMode.ObserveOnly,
            BufferCopyEvidenceSink = accumulator,
        });

        runtime.TryPublishBufferCopyObservation(
            QuicBufferCopyPath.FormattedStreamPayload,
            QuicBufferCopyOperation.Format,
            QuicBufferCopyDecisionBoundary.PacketPlan,
            joinOperationSequence: null,
            logicalBytes: 100,
            copiedBytes: 100,
            sourceSegmentCount: 1,
            requestedCapacityBytes: 120,
            retainedCapacityBytes: 128);
        runtime.TryPublishBufferCopyObservation(
            QuicBufferCopyPath.CombinedApplicationSend,
            QuicBufferCopyOperation.Combine,
            QuicBufferCopyDecisionBoundary.PacketPlan,
            joinOperationSequence: null,
            logicalBytes: 200,
            copiedBytes: 200,
            sourceSegmentCount: 2,
            requestedCapacityBytes: 200,
            retainedCapacityBytes: 256);
        runtime.TryPublishBufferCopyObservation(
            QuicBufferCopyPath.RetransmissionClone,
            QuicBufferCopyOperation.Clone,
            QuicBufferCopyDecisionBoundary.RetransmissionClone,
            joinOperationSequence: 7,
            logicalBytes: 50,
            copiedBytes: 50,
            sourceSegmentCount: 1,
            requestedCapacityBytes: 50,
            retainedCapacityBytes: 64);
        runtime.TryPublishBufferCopyObservation(
            QuicBufferCopyPath.ReceiveSegment,
            QuicBufferCopyOperation.Copy,
            QuicBufferCopyDecisionBoundary.ReceiveSegmentInsertion,
            joinOperationSequence: null,
            logicalBytes: 25,
            copiedBytes: 25,
            sourceSegmentCount: 1,
            requestedCapacityBytes: 25,
            retainedCapacityBytes: 32);

        QuicBufferCopyEpochSummary summary =
            accumulator.CaptureAndReset();
        Assert.True(summary.HasObservation);
        Assert.Equal(1UL, summary.FirstOperationSequence);
        Assert.Equal(4UL, summary.LastOperationSequence);
        Assert.Equal(4UL, summary.OperationCount);
        Assert.Equal(1UL, summary.FormattedStreamPayloadCount);
        Assert.Equal(1UL, summary.CombinedApplicationSendCount);
        Assert.Equal(1UL, summary.RetransmissionCloneCount);
        Assert.Equal(1UL, summary.ReceiveSegmentCount);
        Assert.Equal(1UL, summary.CopyCount);
        Assert.Equal(1UL, summary.FormatCount);
        Assert.Equal(1UL, summary.CombineCount);
        Assert.Equal(1UL, summary.CloneCount);
        Assert.Equal(375UL, summary.TotalLogicalBytes);
        Assert.Equal(375UL, summary.TotalCopiedBytes);
        Assert.Equal(480UL, summary.TotalRetainedCapacityBytes);
        Assert.True(
            (summary.Validity
                & QuicBufferCopyValidity.MissingTerminalReleaseCorrelation)
            != 0);

        Assert.False(accumulator.CaptureAndReset().HasObservation);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ObservationConfigurationRequiresAnExactModeAndSinkPair()
    {
        using QuicConnectionRuntime missingSink = new(
            QuicConnectionStreamStateTestHelpers.CreateState());
        Assert.Throws<InvalidOperationException>(
            () => missingSink.ConfigureAdaptiveRuntimePolicy(
                new QuicServerConnectionOptions
                {
                    BufferCopyObservationMode =
                        QuicBufferCopyObservationMode.ObserveOnly,
                }));

        using QuicConnectionRuntime disabledWithSink = new(
            QuicConnectionStreamStateTestHelpers.CreateState());
        Assert.Throws<InvalidOperationException>(
            () => disabledWithSink.ConfigureAdaptiveRuntimePolicy(
                new QuicServerConnectionOptions
                {
                    BufferCopyEvidenceSink =
                        new QuicBufferCopyEpochAccumulator(),
                }));

        using QuicConnectionRuntime invalidMode = new(
            QuicConnectionStreamStateTestHelpers.CreateState());
        Assert.Throws<ArgumentOutOfRangeException>(
            () => invalidMode.ConfigureAdaptiveRuntimePolicy(
                new QuicServerConnectionOptions
                {
                    BufferCopyObservationMode =
                        (QuicBufferCopyObservationMode)byte.MaxValue,
                }));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ListenerOptionCopyPreservesBufferObservationModeAndSink()
    {
        QuicBufferCopyEpochAccumulator sink = new();
        QuicServerConnectionOptions selectedOptions = new();
        QuicServerConnectionOptions returnedOptions = new()
        {
            BufferCopyObservationMode =
                QuicBufferCopyObservationMode.ObserveOnly,
            BufferCopyEvidenceSink = sink,
        };

        QuicListenerHost.ApplyReturnedOptions(
            selectedOptions,
            returnedOptions);

        Assert.Equal(
            QuicBufferCopyObservationMode.ObserveOnly,
            selectedOptions.BufferCopyObservationMode);
        Assert.Same(sink, selectedOptions.BufferCopyEvidenceSink);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ThrowingEvidenceSinkCannotInterruptCopyOwnershipPath()
    {
        using QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState());
        runtime.ConfigureAdaptiveRuntimePolicy(new QuicServerConnectionOptions
        {
            BufferCopyObservationMode =
                QuicBufferCopyObservationMode.ObserveOnly,
            BufferCopyEvidenceSink = new ThrowingSink(),
        });

        runtime.TryPublishBufferCopyObservation(
            QuicBufferCopyPath.OversizedRawQueue,
            QuicBufferCopyOperation.Copy,
            QuicBufferCopyDecisionBoundary.LogicalWriteAdmission,
            joinOperationSequence: 1,
            logicalBytes: 64,
            copiedBytes: 64,
            sourceSegmentCount: 1,
            requestedCapacityBytes: 64,
            retainedCapacityBytes: 64);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RejectedConstructionCannotCreateOrphanReleaseToken()
    {
        using QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState());
        runtime.ConfigureAdaptiveRuntimePolicy(new QuicServerConnectionOptions
        {
            BufferCopyObservationMode =
                QuicBufferCopyObservationMode.ObserveOnly,
            BufferCopyEvidenceSink = new RejectingSink(),
        });

        QuicBufferCopyLifetimeToken token =
            runtime.TryPublishBufferCopyObservation(
                QuicBufferCopyPath.ReceiveSegment,
                QuicBufferCopyOperation.Copy,
                QuicBufferCopyDecisionBoundary.ReceiveSegmentInsertion,
                joinOperationSequence: null,
                logicalBytes: 64,
                copiedBytes: 64,
                sourceSegmentCount: 1,
                requestedCapacityBytes: 64,
                retainedCapacityBytes: 64,
                trackTerminalRelease: true);

        Assert.True(token.IsEmpty);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void MaintainedQueueRetentionTracksOwnershipTransitions()
    {
        QuicApplicationSendQueue queue = new();
        byte[] first = QuicBufferPool.RentBytes(
            20,
            QuicBufferPoolOwner.QueuedRawStreamData);
        byte[] second = QuicBufferPool.RentBytes(
            40,
            QuicBufferPoolOwner.QueuedRawStreamData);
        byte[] replacement = QuicBufferPool.RentBytes(
            80,
            QuicBufferPoolOwner.QueuedRawStreamData);
        queue.Enqueue(
            streamId: 1,
            priority: 0,
            first,
            streamPayloadLength: 20,
            firstEnqueuedAtMicros: 1_000);
        queue.Enqueue(
            streamId: 2,
            priority: 0,
            second,
            streamPayloadLength: 40,
            firstEnqueuedAtMicros: 2_000);

        QuicRetentionSnapshot initial =
            queue.CaptureRetentionSnapshot(nowMicros: 5_000);
        Assert.Equal(2, initial.RetainedBufferCount);
        Assert.Equal(
            first.Length + second.Length,
            initial.RetainedByteCount);
        Assert.Equal(4, initial.OldestAgeMilliseconds);

        Assert.True(queue.TryGetLatestQueuedWriteForStream(
            streamId: 1,
            out PendingApplicationSendRequest firstRequest));
        Assert.True(queue.TryReplaceQueuedWritePayload(
            firstRequest.Sequence,
            replacement,
            streamPayloadLength: 80));
        QuicRetentionSnapshot replaced =
            queue.CaptureRetentionSnapshot(nowMicros: 5_000);
        Assert.Equal(
            replacement.Length + second.Length,
            replaced.RetainedByteCount);

        Assert.True(queue.TryRemoveQueuedWrite(
            firstRequest.Sequence,
            returnPayloads: true));
        QuicRetentionSnapshot remaining =
            queue.CaptureRetentionSnapshot(nowMicros: 5_000);
        Assert.Equal(1, remaining.RetainedBufferCount);
        Assert.Equal(second.Length, remaining.RetainedByteCount);
        Assert.Equal(3, remaining.OldestAgeMilliseconds);

        queue.Clear();
        QuicRetentionSnapshot empty =
            queue.CaptureRetentionSnapshot(nowMicros: 5_000);
        Assert.Equal(0, empty.RetainedBufferCount);
        Assert.Equal(0, empty.RetainedByteCount);
        Assert.Null(empty.OldestAgeMilliseconds);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void MaintainedRetransmissionRetentionTracksOwnershipTransitions()
    {
        QuicRetransmissionQueue queue = new();
        byte[] first = QuicBufferPool.RentBytes(
            20,
            QuicBufferPoolOwner.Retransmission);
        byte[] second = QuicBufferPool.RentBytes(
            40,
            QuicBufferPoolOwner.Retransmission);
        byte[] shared = QuicBufferPool.RentBytes(
            80,
            QuicBufferPoolOwner.Retransmission);
        queue.QueueRetransmission(new QuicConnectionRetransmissionPlan(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 1,
            PayloadBytes: 20,
            SentAtMicros: 1_000,
            ProbePacket: false,
            CryptoMetadata: null,
            PacketBytes: default,
            PlaintextPayload: first.AsMemory(0, 20),
            PlaintextPayloadOwner: first));
        queue.QueueRetransmission(new QuicConnectionRetransmissionPlan(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 2,
            PayloadBytes: 40,
            SentAtMicros: 2_000,
            ProbePacket: false,
            CryptoMetadata: null,
            PacketBytes: second.AsMemory(0, 40),
            PacketBytesOwner: second));
        queue.QueueRetransmission(new QuicConnectionRetransmissionPlan(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 3,
            PayloadBytes: 80,
            SentAtMicros: 3_000,
            ProbePacket: false,
            CryptoMetadata: null,
            PacketBytes: shared.AsMemory(0, 80),
            PlaintextPayload: shared.AsMemory(0, 80),
            PlaintextPayloadOwner: shared,
            PacketBytesOwner: shared));

        QuicRetentionSnapshot initial =
            queue.CaptureRetentionSnapshot(nowMicros: 5_000);
        Assert.Equal(3, initial.RetainedBufferCount);
        Assert.Equal(
            first.Length + second.Length + shared.Length,
            initial.RetainedByteCount);
        Assert.Equal(4, initial.OldestAgeMilliseconds);

        Assert.True(
            queue.TryDiscardPendingRetransmissionsOlderThan(2_000));
        QuicRetentionSnapshot retained =
            queue.CaptureRetentionSnapshot(nowMicros: 5_000);
        Assert.Equal(2, retained.RetainedBufferCount);
        Assert.Equal(
            second.Length + shared.Length,
            retained.RetainedByteCount);
        Assert.Equal(3, retained.OldestAgeMilliseconds);

        Assert.True(queue.TryDequeueRetransmission(
            out QuicConnectionRetransmissionPlan dequeuedSecond));
        QuicConnectionSendRuntime.ReleaseRetransmissionPlanResources(
            dequeuedSecond);
        QuicRetentionSnapshot remaining =
            queue.CaptureRetentionSnapshot(nowMicros: 5_000);
        Assert.Equal(1, remaining.RetainedBufferCount);
        Assert.Equal(shared.Length, remaining.RetainedByteCount);
        Assert.Equal(2, remaining.OldestAgeMilliseconds);

        Assert.True(queue.TryDequeueRetransmission(
            out QuicConnectionRetransmissionPlan dequeuedShared));
        QuicConnectionSendRuntime.ReleaseRetransmissionPlanResources(
            dequeuedShared);
        QuicRetentionSnapshot empty =
            queue.CaptureRetentionSnapshot(nowMicros: 5_000);
        Assert.Equal(0, empty.RetainedBufferCount);
        Assert.Equal(0, empty.RetainedByteCount);
        Assert.Null(empty.OldestAgeMilliseconds);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void MaintainedSentPacketRetentionTracksOwnershipTransitions()
    {
        QuicConnectionSendRuntime runtime = new();
        byte[] replaced = QuicBufferPool.RentBytes(
            20,
            QuicBufferPoolOwner.SentPacketRetention);
        byte[] replacement = QuicBufferPool.RentBytes(
            40,
            QuicBufferPoolOwner.SentPacketRetention);
        byte[] secondPlaintext = QuicBufferPool.RentBytes(
            80,
            QuicBufferPoolOwner.SentPacketRetention);
        byte[] secondPacket = QuicBufferPool.RentBytes(
            160,
            QuicBufferPoolOwner.SentPacketRetention);
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 1,
            PayloadBytes: 20,
            SentAtMicros: 1_000,
            PacketProtectionLevel: QuicTlsEncryptionLevel.OneRtt,
            PlaintextPayload: replaced.AsMemory(0, 20),
            PlaintextPayloadOwner: replaced));
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 1,
            PayloadBytes: 40,
            SentAtMicros: 1_500,
            PacketProtectionLevel: QuicTlsEncryptionLevel.OneRtt,
            PlaintextPayload: replacement.AsMemory(0, 40),
            PlaintextPayloadOwner: replacement));
        ReadOnlyMemory<byte> protectedPacket =
            secondPacket.AsMemory(0, 160);
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 2,
            PayloadBytes: 160,
            SentAtMicros: 2_000,
            PacketProtectionLevel: QuicTlsEncryptionLevel.OneRtt,
            PacketBytes: protectedPacket,
            PlaintextPayload: secondPlaintext.AsMemory(0, 80),
            PlaintextPayloadOwner: secondPlaintext,
            PacketBytesOwner: secondPacket));

        QuicRetentionSnapshot initial =
            runtime.CaptureSentPacketRetentionSnapshot(
                nowMicros: 5_000,
                out _);
        Assert.Equal(3, initial.RetainedBufferCount);
        Assert.Equal(
            replacement.Length
                + secondPlaintext.Length
                + secondPacket.Length,
            initial.RetainedByteCount);
        Assert.Equal(3.5, initial.OldestAgeMilliseconds);
        Assert.Equal(
            initial,
            runtime.CaptureSentPacketRetentionSnapshot(
                nowMicros: 5_000));

        Assert.True(runtime.TryDetachLatestRebuildablePacketBytes(
            protectedPacket,
            out byte[]? detachedPacket));
        Assert.Same(secondPacket, detachedPacket);
        QuicRetentionSnapshot detached =
            runtime.CaptureSentPacketRetentionSnapshot(
                nowMicros: 5_000);
        Assert.Equal(2, detached.RetainedBufferCount);
        Assert.Equal(
            replacement.Length + secondPlaintext.Length,
            detached.RetainedByteCount);
        QuicBufferPool.ReturnBytes(detachedPacket);

        Assert.True(runtime.TryAcknowledgePacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 1,
            handshakeConfirmed: true));
        QuicRetentionSnapshot remaining =
            runtime.CaptureSentPacketRetentionSnapshot(
                nowMicros: 5_000);
        Assert.Equal(1, remaining.RetainedBufferCount);
        Assert.Equal(
            secondPlaintext.Length,
            remaining.RetainedByteCount);
        Assert.Equal(3, remaining.OldestAgeMilliseconds);

        Assert.True(runtime.TryRegisterLoss(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 2,
            handshakeConfirmed: true));
        QuicRetentionSnapshot empty =
            runtime.CaptureSentPacketRetentionSnapshot(
                nowMicros: 5_000);
        Assert.Equal(0, empty.RetainedBufferCount);
        Assert.Equal(0, empty.RetainedByteCount);
        Assert.Null(empty.OldestAgeMilliseconds);

        QuicRetentionSnapshot transferred =
            runtime.CaptureRetransmissionRetentionSnapshot(
                nowMicros: 5_000);
        Assert.Equal(1, transferred.RetainedBufferCount);
        Assert.Equal(
            secondPlaintext.Length,
            transferred.RetainedByteCount);
        Assert.True(runtime.TryDequeueRetransmission(
            out QuicConnectionRetransmissionPlan retransmission));
        QuicConnectionSendRuntime.ReleaseRetransmissionPlanResources(
            retransmission);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ReceiveSegmentProducersReportCopyAndCapacityReuse()
    {
        QuicConnectionStreamState state =
            QuicConnectionStreamStateTestHelpers.CreateState(
                isServer: true,
                connectionReceiveLimit: 8 * 1024,
                peerBidirectionalReceiveLimit: 8 * 1024);
        RecordingSink sink = new();
        using QuicConnectionRuntime runtime = new(state);
        runtime.ConfigureAdaptiveRuntimePolicy(
            new QuicServerConnectionOptions
            {
                BufferCopyObservationMode =
                    QuicBufferCopyObservationMode.ObserveOnly,
                BufferCopyEvidenceSink = sink,
            });

        byte[] first = Enumerable.Repeat((byte)0x31, 1_024).ToArray();
        byte[] second = Enumerable.Repeat((byte)0x32, 1_000).ToArray();
        Assert.True(state.TryReceiveStreamFrame(
            ParseStreamFrame(
                streamId: 0,
                offset: 0,
                first,
                fin: false),
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.True(state.TryReceiveStreamFrame(
            ParseStreamFrame(
                streamId: 0,
                offset: (ulong)first.Length,
                second,
                fin: true),
            out errorCode));
        Assert.Equal(default, errorCode);

        QuicBufferCopyObservation[] observations =
            [.. sink.Observations.Where(
                static observation =>
                    observation.Path
                        == QuicBufferCopyPath.ReceiveSegment)];
        Assert.Equal(2, observations.Length);
        Assert.Equal(
            QuicBufferCopyOperation.Copy,
            observations[0].Operation);
        Assert.Equal(
            QuicBufferCopyOperation.ReuseAndCopy,
            observations[1].Operation);
        Assert.Equal((ulong)first.Length, observations[0].CopiedBytes);
        Assert.Equal(1_000UL, observations[1].CopiedBytes);
        Assert.True(
            observations[0].RetainedCapacityBytes
                >= observations[0].RequestedCapacityBytes);
        Assert.Equal(
            observations[0].RetainedCapacityBytes,
            observations[1].RetainedCapacityBytes);
        Assert.False(observations[0].Validity.HasFlag(
            QuicBufferCopyValidity.MissingTerminalReleaseCorrelation));
        Assert.True(observations[1].Validity.HasFlag(
            QuicBufferCopyValidity.MissingTerminalReleaseCorrelation));

        byte[] destination = new byte[first.Length + second.Length];
        Assert.True(state.TryReadStreamData(
            streamIdValue: 0,
            destination,
            out int bytesWritten,
            out bool completed,
            out _,
            out _,
            out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(destination.Length, bytesWritten);
        Assert.True(completed);
        Assert.Equal(default, state.CaptureReceiveRetentionSnapshot());

        QuicBufferReleaseObservation release =
            Assert.Single(sink.Releases);
        Assert.Equal(
            QuicBufferCopyLifetimeToken.CurrentTokenContractVersion,
            release.TokenContractVersion);
        Assert.Equal(
            observations[0].OperationSequence,
            release.OperationSequence);
        Assert.Equal(
            QuicBufferCopyPath.ReceiveSegment,
            release.Path);
        Assert.Equal(
            QuicBufferReleaseReason.Delivered,
            release.Reason);
        Assert.Equal(
            observations[0].RetainedCapacityBytes,
            release.ReleasedCapacityBytes);
        Assert.Equal(
            QuicBufferReleaseValidity.None,
            release.Validity);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ReceiveSegmentResetReportsAuthoritativeRelease()
    {
        QuicConnectionStreamState state =
            QuicConnectionStreamStateTestHelpers.CreateState(
                isServer: true,
                connectionReceiveLimit: 8 * 1024,
                peerBidirectionalReceiveLimit: 8 * 1024);
        RecordingSink sink = new();
        using QuicConnectionRuntime runtime = new(state);
        runtime.ConfigureAdaptiveRuntimePolicy(
            new QuicServerConnectionOptions
            {
                BufferCopyObservationMode =
                    QuicBufferCopyObservationMode.ObserveOnly,
                BufferCopyEvidenceSink = sink,
            });

        byte[] payload = Enumerable.Repeat((byte)0x41, 512).ToArray();
        Assert.True(state.TryReceiveStreamFrame(
            ParseStreamFrame(
                streamId: 0,
                offset: 0,
                payload,
                fin: false),
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryReceiveResetStreamFrame(
            new QuicResetStreamFrame(
                streamId: 0,
                applicationProtocolErrorCode: 42,
                finalSize: (ulong)payload.Length),
            out _,
            out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(default, state.CaptureReceiveRetentionSnapshot());

        QuicBufferCopyObservation construction =
            Assert.Single(
                sink.Observations,
                static observation =>
                    observation.Path
                        == QuicBufferCopyPath.ReceiveSegment);
        QuicBufferReleaseObservation release =
            Assert.Single(sink.Releases);
        Assert.Equal(
            construction.OperationSequence,
            release.OperationSequence);
        Assert.Equal(
            QuicBufferReleaseReason.Reset,
            release.Reason);
        Assert.Equal(
            construction.RetainedCapacityBytes,
            release.ReleasedCapacityBytes);
        Assert.Equal(
            QuicBufferReleaseValidity.None,
            release.Validity);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ThrowingReleaseObserverCannotInterruptReceiveReturn()
    {
        QuicConnectionStreamState state =
            QuicConnectionStreamStateTestHelpers.CreateState(
                isServer: true,
                connectionReceiveLimit: 8 * 1024,
                peerBidirectionalReceiveLimit: 8 * 1024);
        state.ConfigureBufferCopyOperationObserver(
            new ReleaseThrowingOperationObserver());

        byte[] payload = Enumerable.Repeat((byte)0x51, 256).ToArray();
        Assert.True(state.TryReceiveStreamFrame(
            ParseStreamFrame(
                streamId: 0,
                offset: 0,
                payload,
                fin: true),
            out QuicTransportErrorCode errorCode));
        byte[] destination = new byte[payload.Length];
        Assert.True(state.TryReadStreamData(
            streamIdValue: 0,
            destination,
            out int bytesWritten,
            out bool completed,
            out _,
            out _,
            out errorCode));

        Assert.Equal(payload.Length, bytesWritten);
        Assert.True(completed);
        Assert.Equal(payload, destination);
        Assert.Equal(default, state.CaptureReceiveRetentionSnapshot());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ApplicationWriteRequestOwnerReportsReplacementAndCompletion()
    {
        RecordingSink sink = new();
        await using QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState());
        runtime.ConfigureAdaptiveRuntimePolicy(
            new QuicServerConnectionOptions
            {
                BufferCopyObservationMode =
                    QuicBufferCopyObservationMode.ObserveOnly,
                BufferCopyEvidenceSink = sink,
            });
        QuicConnectionRuntime.StreamActionRequestCompletionSource
            completion = new(runtime);
        completion.Prepare();
        completion.ConfigureWrite(
            QuicConnectionStreamActionKind.Write,
            streamId: 0,
            streamDataLength: 16);

        byte[] first = Enumerable.Repeat((byte)0x61, 16).ToArray();
        Assert.False(completion.EnsureOwnedStreamData(
            first,
            ReadOnlySpan<byte>.Empty));
        TrackApplicationWriteRequestLifetime(
            runtime,
            completion,
            copiedBytes: first.Length,
            sourceSegmentCount: 1,
            reusedCapacity: false,
            joinOperationSequence: 1);

        int replacementLength =
            checked(completion.OwnedStreamDataCapacity + 1);
        byte[] replacement =
            Enumerable.Repeat((byte)0x62, replacementLength).ToArray();
        Assert.False(completion.EnsureOwnedStreamData(
            replacement,
            ReadOnlySpan<byte>.Empty));
        TrackApplicationWriteRequestLifetime(
            runtime,
            completion,
            copiedBytes: replacement.Length,
            sourceSegmentCount: 1,
            reusedCapacity: false,
            joinOperationSequence: 1);

        ValueTask<bool> task = completion.Task;
        completion.TrySetResult();
        Assert.True(await task);

        Assert.False(completion.HasOwnedStreamData);
        Assert.Equal(2, sink.Observations.Count);
        Assert.Equal(2, sink.Releases.Count);
        Assert.Equal(
            QuicBufferReleaseReason.Replaced,
            sink.Releases[0].Reason);
        Assert.Equal(
            QuicBufferReleaseReason.Completed,
            sink.Releases[1].Reason);
        for (int index = 0; index < sink.Releases.Count; index++)
        {
            Assert.Equal(
                sink.Observations[index].OperationSequence,
                sink.Releases[index].OperationSequence);
            Assert.Equal(
                QuicBufferCopyPath.ApplicationWriteRequest,
                sink.Releases[index].Path);
            Assert.Equal(
                sink.Observations[index].RetainedCapacityBytes,
                sink.Releases[index].ReleasedCapacityBytes);
            Assert.Equal(
                QuicBufferReleaseValidity.None,
                sink.Releases[index].Validity);
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task ApplicationWriteRequestCancellationReportsRelease()
    {
        RecordingSink sink = new();
        await using QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState());
        runtime.ConfigureAdaptiveRuntimePolicy(
            new QuicServerConnectionOptions
            {
                BufferCopyObservationMode =
                    QuicBufferCopyObservationMode.ObserveOnly,
                BufferCopyEvidenceSink = sink,
            });
        QuicConnectionRuntime.StreamActionRequestCompletionSource
            completion = new(runtime);
        completion.Prepare();
        completion.ConfigureWrite(
            QuicConnectionStreamActionKind.Write,
            streamId: 0,
            streamDataLength: 32);
        byte[] data = Enumerable.Repeat((byte)0x71, 32).ToArray();
        Assert.False(completion.EnsureOwnedStreamData(
            data,
            ReadOnlySpan<byte>.Empty));
        TrackApplicationWriteRequestLifetime(
            runtime,
            completion,
            copiedBytes: data.Length,
            sourceSegmentCount: 1,
            reusedCapacity: false,
            joinOperationSequence: 2);

        using CancellationTokenSource cancellation = new();
        cancellation.Cancel();
        ValueTask<bool> task = completion.Task;
        completion.TrySetCanceled(cancellation.Token);
        await Assert.ThrowsAsync<OperationCanceledException>(
            () => task.AsTask());

        QuicBufferReleaseObservation release =
            Assert.Single(sink.Releases);
        Assert.Equal(
            Assert.Single(sink.Observations).OperationSequence,
            release.OperationSequence);
        Assert.Equal(
            QuicBufferReleaseReason.Canceled,
            release.Reason);
        Assert.Equal(
            QuicBufferReleaseValidity.None,
            release.Validity);
        Assert.False(completion.HasOwnedStreamData);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ApplicationWriteRequestCapacityReuseKeepsOriginalToken()
    {
        RecordingSink sink = new();
        using QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState());
        runtime.ConfigureAdaptiveRuntimePolicy(
            new QuicServerConnectionOptions
            {
                BufferCopyObservationMode =
                    QuicBufferCopyObservationMode.ObserveOnly,
                BufferCopyEvidenceSink = sink,
            });
        QuicConnectionRuntime.StreamActionRequestCompletionSource
            completion = new(runtime);
        completion.Prepare();
        byte[] first = Enumerable.Repeat((byte)0x31, 64).ToArray();
        Assert.False(completion.EnsureOwnedStreamData(
            first,
            ReadOnlySpan<byte>.Empty));
        TrackApplicationWriteRequestLifetime(
            runtime,
            completion,
            copiedBytes: first.Length,
            sourceSegmentCount: 1,
            reusedCapacity: false,
            joinOperationSequence: 3);

        byte[] second = Enumerable.Repeat((byte)0x32, 32).ToArray();
        Assert.True(completion.EnsureOwnedStreamData(
            second,
            ReadOnlySpan<byte>.Empty));
        TrackApplicationWriteRequestLifetime(
            runtime,
            completion,
            copiedBytes: second.Length,
            sourceSegmentCount: 1,
            reusedCapacity: true,
            joinOperationSequence: 3);
        completion.ReleaseOwnedStreamData(
            QuicBufferReleaseReason.CopiedToNextOwner);

        Assert.Equal(2, sink.Observations.Count);
        Assert.True(sink.Observations[1].Validity.HasFlag(
            QuicBufferCopyValidity.MissingTerminalReleaseCorrelation));
        QuicBufferReleaseObservation release =
            Assert.Single(sink.Releases);
        Assert.Equal(
            sink.Observations[0].OperationSequence,
            release.OperationSequence);
        Assert.Equal(
            QuicBufferReleaseReason.CopiedToNextOwner,
            release.Reason);
        Assert.Equal(
            QuicBufferReleaseValidity.None,
            release.Validity);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void BufferReleaseReportsContradictoryAndOutOfDomainState()
    {
        RecordingSink sink = new();
        using QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState());
        runtime.ConfigureAdaptiveRuntimePolicy(
            new QuicServerConnectionOptions
            {
                BufferCopyObservationMode =
                    QuicBufferCopyObservationMode.ObserveOnly,
                BufferCopyEvidenceSink = sink,
            });
        QuicBufferCopyLifetimeToken tracked =
            runtime.TryPublishBufferCopyObservation(
                QuicBufferCopyPath.ReceiveSegment,
                QuicBufferCopyOperation.Copy,
                QuicBufferCopyDecisionBoundary.ReceiveSegmentInsertion,
                joinOperationSequence: null,
                logicalBytes: 32,
                copiedBytes: 32,
                sourceSegmentCount: 1,
                requestedCapacityBytes: 32,
                retainedCapacityBytes: 64,
                trackTerminalRelease: true);
        ((IQuicBufferCopyOperationObserver)runtime)
            .ObserveBufferRelease(
                in tracked,
                QuicBufferReleaseReason.Completed,
                releasedCapacityBytes: -1);
        QuicBufferCopyLifetimeToken outOfDomain = new(
            OperationSequence: 999,
            (QuicBufferCopyPath)byte.MaxValue,
            ConstructionTicks: 1,
            RetainedCapacityBytes: 1);
        ((IQuicBufferCopyOperationObserver)runtime)
            .ObserveBufferRelease(
                in outOfDomain,
                (QuicBufferReleaseReason)byte.MaxValue,
                releasedCapacityBytes: 1);

        Assert.Equal(2, sink.Releases.Count);
        Assert.True(sink.Releases[0].Validity.HasFlag(
            QuicBufferReleaseValidity.Contradictory));
        Assert.True(sink.Releases[0].Validity.HasFlag(
            QuicBufferReleaseValidity.CapacityMismatch));
        Assert.True(sink.Releases[0].Validity.HasFlag(
            QuicBufferReleaseValidity.ArithmeticSaturated));
        Assert.True(sink.Releases[1].Validity.HasFlag(
            QuicBufferReleaseValidity.OutOfDomain));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PathMigrationCloneProducerReportsOwnedPlaintextCopy()
    {
        QuicConnectionSendRuntime sendRuntime = new();
        RecordingOperationObserver observer = new();
        sendRuntime.ConfigureBufferCopyOperationObserver(observer);
        byte[] owner = QuicBufferPool.RentBytes(
            32,
            QuicBufferPoolOwner.SentPacketRetention);
        owner.AsSpan(0, 32).Fill(0x5A);
        sendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 7,
            PayloadBytes: 32,
            SentAtMicros: 1_000,
            PacketProtectionLevel: QuicTlsEncryptionLevel.OneRtt,
            PlaintextPayload: owner.AsMemory(0, 32),
            PlaintextPayloadOwner: owner));

        Assert.True(
            sendRuntime.TryDiscardPacketNumberSpaceForPathMigration(
                QuicPacketNumberSpace.ApplicationData));

        ObservedOperation operation =
            Assert.Single(observer.Operations);
        Assert.Equal(
            QuicBufferCopyPath.RetransmissionClone,
            operation.Path);
        Assert.Equal(
            QuicBufferCopyOperation.Clone,
            operation.Operation);
        Assert.Equal(
            QuicBufferCopyDecisionBoundary.RetransmissionClone,
            operation.DecisionBoundary);
        Assert.Equal(7, operation.JoinOperationSequence);
        Assert.Equal(32, operation.CopiedBytes);
        Assert.True(
            operation.RetainedCapacityBytes
                >= operation.RequestedCapacityBytes);

        Assert.True(sendRuntime.TryDequeueRetransmission(
            out QuicConnectionRetransmissionPlan retransmission));
        Assert.NotSame(owner, retransmission.PlaintextPayloadOwner);
        Assert.Equal(
            Enumerable.Repeat((byte)0x5A, 32),
            retransmission.PlaintextPayload.ToArray());
        QuicConnectionSendRuntime.ReleaseRetransmissionPlanResources(
            retransmission);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ThrowingOperationObserverCannotInterruptMigrationClone()
    {
        QuicConnectionSendRuntime sendRuntime = new();
        sendRuntime.ConfigureBufferCopyOperationObserver(
            new ThrowingOperationObserver());
        byte[] owner = QuicBufferPool.RentBytes(
            8,
            QuicBufferPoolOwner.SentPacketRetention);
        owner.AsSpan(0, 8).Fill(0x7B);
        byte[] expected = owner.AsSpan(0, 8).ToArray();
        sendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 9,
            PayloadBytes: 8,
            SentAtMicros: 1_000,
            PacketProtectionLevel: QuicTlsEncryptionLevel.OneRtt,
            PlaintextPayload: owner.AsMemory(0, 8),
            PlaintextPayloadOwner: owner));

        Assert.True(
            sendRuntime.TryDiscardPacketNumberSpaceForPathMigration(
                QuicPacketNumberSpace.ApplicationData));
        Assert.True(sendRuntime.TryDequeueRetransmission(
            out QuicConnectionRetransmissionPlan retransmission));
        Assert.Equal(
            expected,
            retransmission.PlaintextPayload.ToArray());
        QuicConnectionSendRuntime.ReleaseRetransmissionPlanResources(
            retransmission);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ObservationAndEpochSummaryPassSchemaAndSemanticValidation()
    {
        string repoRoot =
            AdaptiveRuntimePolicyScriptTestSupport.FindRepoRoot();
        string temporaryDirectory = Path.Combine(
            repoRoot,
            ".artifacts",
            "adaptive-runtime",
            $"buffer-copy-validator-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(temporaryDirectory);

        try
        {
            RecordingSink sink = new();
            using QuicConnectionRuntime runtime = new(
                QuicConnectionStreamStateTestHelpers.CreateState());
            runtime.ConfigureAdaptiveRuntimePolicy(
                new QuicServerConnectionOptions
                {
                    BufferCopyObservationMode =
                        QuicBufferCopyObservationMode.ObserveOnly,
                    BufferCopyEvidenceSink = sink,
                });
            runtime.TryPublishBufferCopyObservation(
                QuicBufferCopyPath.SentPacketPlaintextRetention,
                QuicBufferCopyOperation.Retain,
                QuicBufferCopyDecisionBoundary.SentPacketRetention,
                joinOperationSequence: 7,
                logicalBytes: 80,
                copiedBytes: 80,
                sourceSegmentCount: 1,
                requestedCapacityBytes: 80,
                retainedCapacityBytes: 128);
            QuicBufferCopyObservation observation =
                Assert.Single(sink.Observations);
            QuicBufferCopyEpochAccumulator accumulator = new();
            Assert.True(accumulator.TryPublish(in observation));
            QuicBufferCopyEpochSummary summary =
                accumulator.CaptureAndReset();

            JsonSerializerOptions options =
                new(JsonSerializerDefaults.Web);
            options.Converters.Add(new JsonStringEnumConverter());
            string observationPath = Path.Combine(
                temporaryDirectory,
                "buffer-copy-observations.jsonl");
            string epochPath = Path.Combine(
                temporaryDirectory,
                "buffer-copy-epoch.json");
            File.WriteAllText(
                observationPath,
                JsonSerializer.Serialize(observation, options));
            File.WriteAllText(
                epochPath,
                JsonSerializer.Serialize(summary, options));

            AdaptiveRuntimePolicyScriptTestSupport.ProcessResult result =
                AdaptiveRuntimePolicyScriptTestSupport.RunPowerShellFile(
                    "eng/adaptive-runtime/Test-AdaptiveRuntimeBufferCopyEvidence.ps1",
                    "-ObservationPath",
                    observationPath,
                    "-EpochSummaryPath",
                    epochPath);

            Assert.True(result.ExitCode == 0, result.Output);
            using JsonDocument validation =
                JsonDocument.Parse(result.Output);
            Assert.True(
                validation.RootElement.GetProperty("valid").GetBoolean());
            Assert.Equal(
                1,
                validation.RootElement
                    .GetProperty("observationRowCount")
                    .GetInt32());
            Assert.Equal(
                1,
                validation.RootElement
                    .GetProperty("operationCount")
                    .GetInt32());
        }
        finally
        {
            Directory.Delete(temporaryDirectory, recursive: true);
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void BufferLifetimeRawRecordsPassSchemaAndExactJoinValidation()
    {
        string repoRoot =
            AdaptiveRuntimePolicyScriptTestSupport.FindRepoRoot();
        string temporaryDirectory = Path.Combine(
            repoRoot,
            ".artifacts",
            "adaptive-runtime",
            $"buffer-lifetime-validator-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(temporaryDirectory);

        try
        {
            RecordingSink sink = new();
            using QuicConnectionRuntime runtime = new(
                QuicConnectionStreamStateTestHelpers.CreateState());
            runtime.ConfigureAdaptiveRuntimePolicy(
                new QuicServerConnectionOptions
                {
                    BufferCopyObservationMode =
                        QuicBufferCopyObservationMode.ObserveOnly,
                    BufferCopyEvidenceSink = sink,
                });
            QuicBufferCopyLifetimeToken token =
                runtime.TryPublishBufferCopyObservation(
                    QuicBufferCopyPath.ReceiveSegment,
                    QuicBufferCopyOperation.Copy,
                    QuicBufferCopyDecisionBoundary.ReceiveSegmentInsertion,
                    joinOperationSequence: null,
                    logicalBytes: 80,
                    copiedBytes: 80,
                    sourceSegmentCount: 1,
                    requestedCapacityBytes: 80,
                    retainedCapacityBytes: 128,
                    trackTerminalRelease: true);
            ((IQuicBufferCopyOperationObserver)runtime)
                .ObserveBufferRelease(
                    in token,
                    QuicBufferReleaseReason.Delivered,
                    releasedCapacityBytes: 128);

            QuicBufferCopyObservation copy =
                Assert.Single(sink.Observations);
            QuicBufferReleaseObservation release =
                Assert.Single(sink.Releases);
            JsonSerializerOptions options =
                new(JsonSerializerDefaults.Web);
            options.Converters.Add(new JsonStringEnumConverter());
            string copyPath = Path.Combine(
                temporaryDirectory,
                "buffer-copy.raw.jsonl");
            string releasePath = Path.Combine(
                temporaryDirectory,
                "buffer-release.raw.jsonl");
            File.WriteAllText(
                copyPath,
                JsonSerializer.Serialize(
                    new
                    {
                        schemaVersion = "quic-buffer-copy-raw-v2",
                        connectionKey = "connection-0001",
                        observation = copy,
                    },
                    options));
            File.WriteAllText(
                releasePath,
                JsonSerializer.Serialize(
                    new
                    {
                        schemaVersion = "quic-buffer-release-raw-v2",
                        connectionKey = "connection-0001",
                        observation = release,
                    },
                    options));

            AdaptiveRuntimePolicyScriptTestSupport.ProcessResult result =
                AdaptiveRuntimePolicyScriptTestSupport.RunPowerShellFile(
                    "eng/adaptive-runtime/Test-AdaptiveRuntimeBufferLifetimeEvidence.ps1",
                    "-CopyPath",
                    copyPath,
                    "-ReleasePath",
                    releasePath);

            Assert.True(result.ExitCode == 0, result.Output);
            using JsonDocument validation =
                JsonDocument.Parse(result.Output);
            Assert.True(
                validation.RootElement.GetProperty("valid").GetBoolean());
            Assert.Equal(
                1,
                validation.RootElement
                    .GetProperty("copyRowCount")
                    .GetInt32());
            Assert.Equal(
                1,
                validation.RootElement
                    .GetProperty("trackedCopyRowCount")
                    .GetInt32());
            Assert.Equal(
                1,
                validation.RootElement
                    .GetProperty("releaseRowCount")
                    .GetInt32());
            Assert.Equal(
                1,
                validation.RootElement
                    .GetProperty("exactJoinCount")
                    .GetInt32());
        }
        finally
        {
            Directory.Delete(temporaryDirectory, recursive: true);
        }
    }

    private sealed class RecordingSink :
        IQuicBufferCopyEvidenceSink,
        IQuicBufferReleaseEvidenceSink
    {
        internal List<QuicBufferCopyObservation> Observations { get; } = [];
        internal List<QuicBufferReleaseObservation> Releases { get; } = [];

        public bool TryPublish(
            in QuicBufferCopyObservation observation)
        {
            Observations.Add(observation);
            return true;
        }

        public bool TryPublish(
            in QuicBufferReleaseObservation observation)
        {
            Releases.Add(observation);
            return true;
        }
    }

    private sealed class ThrowingSink :
        IQuicBufferCopyEvidenceSink,
        IQuicBufferReleaseEvidenceSink
    {
        public bool TryPublish(
            in QuicBufferCopyObservation observation)
            => throw new InvalidOperationException("diagnostic sink failure");

        public bool TryPublish(
            in QuicBufferReleaseObservation observation)
            => throw new InvalidOperationException("diagnostic sink failure");
    }

    private sealed class RejectingSink :
        IQuicBufferCopyEvidenceSink,
        IQuicBufferReleaseEvidenceSink
    {
        public bool TryPublish(
            in QuicBufferCopyObservation observation)
            => false;

        public bool TryPublish(
            in QuicBufferReleaseObservation observation)
            => false;
    }

    private sealed class RecordingOperationObserver :
        IQuicBufferCopyOperationObserver
    {
        internal List<ObservedOperation> Operations { get; } = [];
        internal List<QuicBufferReleaseObservation> Releases { get; } = [];
        private ulong nextOperationSequence;

        public QuicBufferCopyLifetimeToken ObserveBufferCopy(
            QuicBufferCopyPath path,
            QuicBufferCopyOperation operation,
            QuicBufferCopyDecisionBoundary decisionBoundary,
            long? joinOperationSequence,
            int logicalBytes,
            int copiedBytes,
            int sourceSegmentCount,
            int requestedCapacityBytes,
            int retainedCapacityBytes,
            bool trackTerminalRelease)
        {
            Operations.Add(new ObservedOperation(
                path,
                operation,
                decisionBoundary,
                joinOperationSequence,
                logicalBytes,
                copiedBytes,
                sourceSegmentCount,
                requestedCapacityBytes,
                retainedCapacityBytes));
            ulong sequence = ++nextOperationSequence;
            return trackTerminalRelease
                ? new QuicBufferCopyLifetimeToken(
                    sequence,
                    path,
                    ConstructionTicks: 1,
                    (ulong)retainedCapacityBytes)
                : default;
        }

        public void ObserveBufferRelease(
            in QuicBufferCopyLifetimeToken token,
            QuicBufferReleaseReason reason,
            int releasedCapacityBytes)
            => Releases.Add(new QuicBufferReleaseObservation(
                ReleaseSequence: (ulong)Releases.Count + 1,
                token.OperationSequence,
                token.Path,
                reason,
                (ulong)releasedCapacityBytes,
                LifetimeMicros: 1,
                QuicConnectionPhase.Active,
                DisposalStarted: false,
                QuicBufferReleaseValidity.None));
    }

    private sealed class ThrowingOperationObserver :
        IQuicBufferCopyOperationObserver
    {
        public QuicBufferCopyLifetimeToken ObserveBufferCopy(
            QuicBufferCopyPath path,
            QuicBufferCopyOperation operation,
            QuicBufferCopyDecisionBoundary decisionBoundary,
            long? joinOperationSequence,
            int logicalBytes,
            int copiedBytes,
            int sourceSegmentCount,
            int requestedCapacityBytes,
            int retainedCapacityBytes,
            bool trackTerminalRelease)
            => throw new InvalidOperationException(
                "diagnostic operation observer failure");

        public void ObserveBufferRelease(
            in QuicBufferCopyLifetimeToken token,
            QuicBufferReleaseReason reason,
            int releasedCapacityBytes)
            => throw new InvalidOperationException(
                "diagnostic operation observer failure");
    }

    private sealed class ReleaseThrowingOperationObserver :
        IQuicBufferCopyOperationObserver
    {
        private ulong nextOperationSequence;

        public QuicBufferCopyLifetimeToken ObserveBufferCopy(
            QuicBufferCopyPath path,
            QuicBufferCopyOperation operation,
            QuicBufferCopyDecisionBoundary decisionBoundary,
            long? joinOperationSequence,
            int logicalBytes,
            int copiedBytes,
            int sourceSegmentCount,
            int requestedCapacityBytes,
            int retainedCapacityBytes,
            bool trackTerminalRelease)
            => trackTerminalRelease
                ? new QuicBufferCopyLifetimeToken(
                    ++nextOperationSequence,
                    path,
                    ConstructionTicks: 1,
                    (ulong)retainedCapacityBytes)
                : default;

        public void ObserveBufferRelease(
            in QuicBufferCopyLifetimeToken token,
            QuicBufferReleaseReason reason,
            int releasedCapacityBytes)
            => throw new InvalidOperationException(
                "diagnostic release observer failure");
    }

    private readonly record struct ObservedOperation(
        QuicBufferCopyPath Path,
        QuicBufferCopyOperation Operation,
        QuicBufferCopyDecisionBoundary DecisionBoundary,
        long? JoinOperationSequence,
        int LogicalBytes,
        int CopiedBytes,
        int SourceSegmentCount,
        int RequestedCapacityBytes,
        int RetainedCapacityBytes);

    private static void TrackApplicationWriteRequestLifetime(
        QuicConnectionRuntime runtime,
        QuicConnectionRuntime.StreamActionRequestCompletionSource
            completion,
        int copiedBytes,
        int sourceSegmentCount,
        bool reusedCapacity,
        long joinOperationSequence)
    {
        QuicBufferCopyLifetimeToken token =
            runtime.TryPublishBufferCopyObservation(
                QuicBufferCopyPath.ApplicationWriteRequest,
                reusedCapacity
                    ? QuicBufferCopyOperation.ReuseAndCopy
                    : QuicBufferCopyOperation.Copy,
                QuicBufferCopyDecisionBoundary.StreamWriteRetry,
                joinOperationSequence,
                copiedBytes,
                copiedBytes,
                sourceSegmentCount,
                copiedBytes,
                completion.OwnedStreamDataCapacity,
                trackTerminalRelease: !reusedCapacity);
        if (!reusedCapacity)
        {
            completion.SetOwnedStreamDataLifetimeToken(
                in token);
        }
    }

    private static QuicStreamFrame ParseStreamFrame(
        ulong streamId,
        ulong offset,
        ReadOnlySpan<byte> payload,
        bool fin)
    {
        byte frameType =
            QuicStreamFrameBits.StreamFrameTypeMinimum
            | QuicStreamFrameBits.LengthBitMask;
        if (offset != 0)
        {
            frameType |= QuicStreamFrameBits.OffsetBitMask;
        }

        if (fin)
        {
            frameType |= QuicStreamFrameBits.FinBitMask;
        }

        byte[] buffer = new byte[payload.Length + 32];
        Assert.True(QuicFrameCodec.TryFormatStreamFrame(
            frameType,
            streamId,
            offset,
            payload,
            buffer,
            out int bytesWritten));
        Assert.True(QuicStreamParser.TryParseStreamFrame(
            buffer.AsSpan(0, bytesWritten),
            out QuicStreamFrame frame));
        return frame;
    }
}
