// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.Concurrent;

namespace Incursa.Quic;

// Stream actions, flow-control publication, outbound payload construction, and observer plumbing.
internal sealed partial class QuicConnectionRuntime
{
    private static readonly bool ApplicationSendDebugEnabled =
        string.Equals(
            Environment.GetEnvironmentVariable("INCURSA_QUIC_DEBUG_APP_RX"),
            "1",
            StringComparison.Ordinal);
    private const string StreamWriteSendBlockedMessage = "The connection cannot send the stream write packet.";
    private const string QueuedStreamWriteSendBlockedMessage = "The connection cannot send the queued stream write packet.";
    private const string DatagramSendBlockedMessage = "The connection cannot send the DATAGRAM packet.";

    private bool HandleStreamAction(
        QuicConnectionStreamActionEvent streamActionEvent,
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        return streamActionEvent.ActionKind switch
        {
            QuicConnectionStreamActionKind.Open
                when streamActionEvent.StreamType is QuicStreamType streamType
                => HandleOpenStreamAction(streamActionEvent.RequestId, streamType, ref effects),
            QuicConnectionStreamActionKind.Write
                when streamActionEvent.StreamId.HasValue
                => HandleWriteStreamAction(
                    nowTicks,
                    streamActionEvent.RequestId,
                    streamActionEvent.StreamId.Value,
                    streamActionEvent.StreamData,
                    finishWrites: false,
                    ref effects),
            QuicConnectionStreamActionKind.Finish
                when streamActionEvent.StreamId.HasValue
                => HandleWriteStreamAction(
                    nowTicks,
                    streamActionEvent.RequestId,
                    streamActionEvent.StreamId.Value,
                    streamActionEvent.StreamData,
                    finishWrites: true,
                    ref effects),
            QuicConnectionStreamActionKind.Reset
                when streamActionEvent.StreamId.HasValue && streamActionEvent.ApplicationErrorCode.HasValue
                => HandleResetStreamAction(
                    streamActionEvent.RequestId,
                    streamActionEvent.StreamId.Value,
                    streamActionEvent.ApplicationErrorCode.Value,
                    ref effects),
            QuicConnectionStreamActionKind.StopSending
                when streamActionEvent.StreamId.HasValue && streamActionEvent.ApplicationErrorCode.HasValue
                => HandleStopSendingStreamAction(
                    streamActionEvent.RequestId,
                    streamActionEvent.StreamId.Value,
                    streamActionEvent.ApplicationErrorCode.Value,
                    ref effects),
            QuicConnectionStreamActionKind.ReleaseCapacity
                when streamActionEvent.StreamId.HasValue
                => HandleReleaseCapacityStreamAction(
                    streamActionEvent.StreamId.Value,
                    ref effects),
            _ => false,
        };
    }

    private bool HandleDatagramSendRequested(
        QuicConnectionDatagramSendRequestedEvent datagramSendRequestedEvent,
        ref List<QuicConnectionEffect>? effects)
    {
        if (!pendingDatagramSendRequests.TryRemove(
                datagramSendRequestedEvent.RequestId,
                out TaskCompletionSource<object?>? completion))
        {
            return false;
        }

        if (!TryValidateDatagramSendBoundary(out Exception? exception))
        {
            completion.TrySetException(exception!);
            return false;
        }

        ulong? peerMaxDatagramFrameSize = tlsState.PeerTransportParameters?.MaxDatagramFrameSize;
        if (!peerMaxDatagramFrameSize.HasValue || peerMaxDatagramFrameSize.Value == 0)
        {
            completion.TrySetException(new InvalidOperationException(
                "The peer did not advertise QUIC DATAGRAM support."));
            return false;
        }

        if (!TryBuildOutboundDatagramPayload(
                datagramSendRequestedEvent.DatagramData,
                out byte[] datagramPayload))
        {
            completion.TrySetException(new InvalidOperationException(
                "The connection runtime could not build the DATAGRAM payload."));
            return false;
        }

        if ((ulong)datagramPayload.Length > peerMaxDatagramFrameSize.Value)
        {
            completion.TrySetException(new InvalidOperationException(
                "The DATAGRAM frame exceeds the peer max_datagram_frame_size."));
            return false;
        }

        byte[] packetPayload = PadApplicationPayloadForProtection(datagramPayload);
        QuicConnectionPathIdentity selectedPathIdentity = activePath!.Value.Identity;
        if (TryGetPermittedPeerMigrationSendPath(out QuicConnectionPathIdentity peerMigrationPathIdentity))
        {
            selectedPathIdentity = peerMigrationPathIdentity;
        }

        if (!TryProtectAndAccountApplicationPayloadOnPath(
                selectedPathIdentity,
                packetPayload,
                "The connection runtime could not protect the DATAGRAM packet.",
                DatagramSendBlockedMessage,
                ref effects,
                out QuicConnectionPathIdentity sendPathIdentity,
                out ReadOnlyMemory<byte> protectedPacket,
                out exception,
                retransmittable: false,
                probePacket: false,
                includeAckFrame: true,
                streamIds: null,
                enforcePathMaximumDatagramSize: true))
        {
            if (IsTransientApplicationSendPathBlocked(exception))
            {
                completion.TrySetResult(null);
                return false;
            }

            completion.TrySetException(exception!);
            return false;
        }

        AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(
            sendPathIdentity,
            protectedPacket));
        AppendEffects(ref effects, RecomputeLifecycleTimerEffects());
        completion.TrySetResult(null);
        return true;
    }

    private bool HandleOpenStreamAction(
        long requestId,
        QuicStreamType streamType,
        ref List<QuicConnectionEffect>? effects)
    {
        if (!TryProcessPendingStreamOpenRequest(requestId, streamType, ref effects, out bool stillPending))
        {
            return false;
        }

        _ = stillPending;
        return true;
    }

    private bool TryRetryPendingStreamOpenRequests(
        bool bidirectional,
        ref List<QuicConnectionEffect>? effects)
    {
        if (pendingStreamOpenTypes.IsEmpty)
        {
            return false;
        }

        bool stateChanged = false;
        KeyValuePair<long, QuicStreamType>[] pendingRequests = pendingStreamOpenTypes.ToArray();
        Array.Sort(pendingRequests, static (left, right) => left.Key.CompareTo(right.Key));

        foreach (KeyValuePair<long, QuicStreamType> pendingRequest in pendingRequests)
        {
            if ((pendingRequest.Value == QuicStreamType.Bidirectional) != bidirectional)
            {
                continue;
            }

            if (!TryProcessPendingStreamOpenRequest(
                pendingRequest.Key,
                pendingRequest.Value,
                ref effects,
                out bool stillPending))
            {
                continue;
            }

            if (stillPending)
            {
                return stateChanged;
            }

            stateChanged = true;
        }

        return stateChanged;
    }

    private bool TryProcessPendingStreamOpenRequest(
        long requestId,
        QuicStreamType streamType,
        ref List<QuicConnectionEffect>? effects,
        out bool stillPending)
    {
        stillPending = false;

        if (!pendingStreamOpenRequests.TryGetValue(requestId, out TaskCompletionSource<ulong>? completion)
            || !pendingStreamOpenTypes.TryGetValue(requestId, out QuicStreamType trackedStreamType)
            || trackedStreamType != streamType)
        {
            return false;
        }

        if (!TryValidateStreamSendBoundary(out Exception? exception))
        {
            if (TryRemovePendingStreamOpenRequest(requestId, out TaskCompletionSource<ulong>? removedCompletion))
            {
                removedCompletion!.TrySetException(exception!);
            }
            else
            {
                completion.TrySetException(exception!);
            }

            return true;
        }

        bool bidirectional = streamType == QuicStreamType.Bidirectional;
        if (!streamRegistry.Bookkeeping.TryPeekLocalStream(
                bidirectional,
                out QuicStreamId streamId,
                out QuicStreamsBlockedFrame blockedFrame))
        {
            _ = TryEmitStreamsBlockedSignal(blockedFrame, ref effects);
            stillPending = true;
            return true;
        }

        if (!TryRemovePendingStreamOpenRequest(requestId, out TaskCompletionSource<ulong>? openCompletion))
        {
            return false;
        }

        if (!TryBuildOutboundStreamPayload(streamId.Value, 0, ReadOnlySpan<byte>.Empty, fin: false, out byte[] streamPayload))
        {
            openCompletion!.TrySetException(new InvalidOperationException("The connection runtime could not build the stream open payload."));
            return true;
        }

        if (!TryProtectAndAccountStreamApplicationPayload(
            streamPayload,
            "The connection runtime could not protect the stream open packet.",
            "The connection cannot send the stream open packet.",
            probePacket: false,
            streamIds: null,
            ref effects,
            out QuicConnectionPathIdentity sendPathIdentity,
            out ReadOnlyMemory<byte> protectedPacket,
            out Exception? payloadException))
        {
            openCompletion!.TrySetException(payloadException!);
            return true;
        }

        if (!streamRegistry.Bookkeeping.TryOpenLocalStream(bidirectional, out QuicStreamId committedStreamId, out QuicStreamsBlockedFrame committedBlockedFrame))
        {
            _ = committedBlockedFrame;
            openCompletion!.TrySetException(new InvalidOperationException("The connection runtime could not commit the stream open."));
            return true;
        }

        if (committedStreamId.Value != streamId.Value)
        {
            openCompletion!.TrySetException(new InvalidOperationException("The connection runtime committed an unexpected outbound stream identifier."));
            return true;
        }

        AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(
            sendPathIdentity,
            protectedPacket));
        AppendEffects(ref effects, RecomputeLifecycleTimerEffects());

        openCompletion!.TrySetResult(committedStreamId.Value);
        return true;
    }

    private bool HandleWriteStreamAction(
        long nowTicks,
        long requestId,
        ulong streamId,
        ReadOnlyMemory<byte> streamData,
        bool finishWrites,
        ref List<QuicConnectionEffect>? effects)
    {
        if (!pendingStreamActionRequests.TryRemove(requestId, out TaskCompletionSource<object?>? completion))
        {
            return false;
        }

        if (!TryValidateStreamSendBoundary(out Exception? exception))
        {
            completion.TrySetException(exception!);
            return false;
        }

        if (!TryResolveOrOpenLocalWritableStreamSnapshot(
                streamId,
                out QuicConnectionStreamSnapshot snapshot,
                out QuicTransportErrorCode openErrorCode))
        {
            completion.TrySetException(openErrorCode != default
                ? new QuicException(
                    QuicError.TransportError,
                    null,
                    (long)openErrorCode,
                    "The stream write could not be committed.")
                : new InvalidOperationException("The stream is not available on this connection."));
            return false;
        }

        if (snapshot.SendState == QuicStreamSendState.None)
        {
            completion.TrySetException(new InvalidOperationException("This stream does not have a writable side."));
            return false;
        }

        if (snapshot.SendState is QuicStreamSendState.DataSent or QuicStreamSendState.ResetSent)
        {
            completion.TrySetException(new InvalidOperationException("The writable side is already completed."));
            return false;
        }

        if (!streamRegistry.Bookkeeping.TryCaptureSendState(streamId, out QuicConnectionStreamSendStateSnapshot sendStateBeforeWrite))
        {
            completion.TrySetException(new InvalidOperationException("The stream send state is unavailable."));
            return false;
        }

        ulong writeOffset = snapshot.UniqueBytesSent;
        if (ApplicationSendDebugEnabled)
        {
            Console.Error.WriteLine(
                $"app-tx role={tlsState.Role} stream={streamId} offset={writeOffset} length={streamData.Length} fin={finishWrites}.");
        }
        if (!streamRegistry.Bookkeeping.TryReserveSendCapacity(
            streamId,
            writeOffset,
            streamData.Length,
            finishWrites,
            out QuicDataBlockedFrame dataBlockedFrame,
            out QuicStreamDataBlockedFrame streamDataBlockedFrame,
            out QuicTransportErrorCode errorCode))
        {
            if (errorCode != default)
            {
                completion.TrySetException(new QuicException(
                    QuicError.TransportError,
                    null,
                    (long)errorCode,
                    "The stream write could not be committed."));
            }
            else if (dataBlockedFrame.MaximumData != 0 || streamDataBlockedFrame.MaximumStreamData != 0)
            {
                _ = TryEmitFlowControlBlockedSignal(dataBlockedFrame, streamDataBlockedFrame, ref effects);
                completion.TrySetException(new NotSupportedException(
                    "Writes that wait for additional flow-control credit are not supported by this slice."));
            }
            else
            {
                completion.TrySetException(new InvalidOperationException("The stream write could not be committed."));
            }

            return false;
        }

        bool queuedWritesPendingForStream = finishWrites
            && streamData.IsEmpty
            && applicationSendQueue.HasPendingWritesForStream(streamId);
        if (queuedWritesPendingForStream)
        {
            if (!TryPromoteQueuedApplicationSendToFinal(streamId))
            {
                return FailWriteAfterRollback(
                    completion,
                    sendStateBeforeWrite,
                    new InvalidOperationException("The connection runtime could not mark the queued stream write as final."));
            }

            if (!FlushPendingApplicationSends(nowTicks, ref effects, out Exception? flushException))
            {
                if (IsTransientApplicationSendPathBlocked(flushException))
                {
                    completion.TrySetResult(null);
                    return true;
                }

                return FailWriteAfterRollback(
                    completion,
                    sendStateBeforeWrite,
                    flushException ?? new InvalidOperationException("The connection runtime could not flush queued stream writes before finishing the writable side."));
            }

            TryReleasePeerStreamCapacity(streamId, ref effects);
            AppendEffects(ref effects, RecomputeLifecycleTimerEffects());
            completion.TrySetResult(null);
            return true;
        }

        if (!TryBuildOutboundStreamPayload(streamId, writeOffset, streamData.Span, finishWrites, out byte[] streamPayload))
        {
            return FailWriteAfterRollback(
                completion,
                sendStateBeforeWrite,
                new InvalidOperationException("The connection runtime could not build the stream write payload."));
        }

        if (!streamRegistry.Bookkeeping.TryGetStreamPriority(streamId, out int streamPriority))
        {
            streamPriority = 0;
        }

        if (sendRuntime.HasPendingRetransmission(QuicPacketNumberSpace.ApplicationData))
        {
            QueuePendingApplicationSend(streamId, streamPriority, streamPayload, nowTicks, ref effects);
            _ = TryFlushPendingRetransmissions(
                QuicPacketNumberSpace.ApplicationData,
                nowTicks,
                probePacket: false,
                ref effects);
            AppendEffects(ref effects, RecomputeLifecycleTimerEffects());
            completion.TrySetResult(null);
            return true;
        }

        if (!finishWrites && ShouldDelayApplicationSend(streamData.Span))
        {
            QueuePendingApplicationSend(streamId, streamPriority, streamPayload, nowTicks, ref effects);
            completion.TrySetResult(null);
            return true;
        }

        if (!TryProtectAndAccountStreamApplicationPayload(
            streamPayload,
            "The connection runtime could not protect the stream write packet.",
            StreamWriteSendBlockedMessage,
            probePacket: false,
            streamIds: new[] { streamId },
            ref effects,
            out QuicConnectionPathIdentity sendPathIdentity,
            out ReadOnlyMemory<byte> protectedPacket,
            out exception))
        {
            if (IsTransientApplicationSendPathBlocked(exception))
            {
                QueuePendingApplicationSend(streamId, streamPriority, streamPayload, nowTicks, ref effects);
                completion.TrySetResult(null);
                return true;
            }

            return FailWriteAfterRollback(
                completion,
                sendStateBeforeWrite,
                exception!);
        }

        AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(
            sendPathIdentity,
            protectedPacket));

        if (finishWrites)
        {
            TryReleasePeerStreamCapacity(streamId, ref effects);
        }

        AppendEffects(ref effects, RecomputeLifecycleTimerEffects());
        completion.TrySetResult(null);
        return true;
    }

    private bool TryResolveOrOpenLocalWritableStreamSnapshot(
        ulong streamId,
        out QuicConnectionStreamSnapshot snapshot,
        out QuicTransportErrorCode errorCode)
    {
        if (streamRegistry.Bookkeeping.TryGetStreamSnapshot(streamId, out snapshot))
        {
            errorCode = default;
            return true;
        }

        QuicStreamId quicStreamId = new(streamId);
        if (!streamRegistry.Bookkeeping.TryPeekLocalStream(
                quicStreamId.IsBidirectional,
                out QuicStreamId nextStreamId,
                out _))
        {
            snapshot = default;
            errorCode = QuicTransportErrorCode.StreamLimitError;
            return false;
        }

        if (nextStreamId.Value != streamId)
        {
            snapshot = default;
            errorCode = default;
            return false;
        }

        if (!streamRegistry.Bookkeeping.TryOpenLocalStream(
                quicStreamId.IsBidirectional,
                out QuicStreamId committedStreamId,
                out _)
            || committedStreamId.Value != streamId
            || !streamRegistry.Bookkeeping.TryGetStreamSnapshot(streamId, out snapshot))
        {
            snapshot = default;
            errorCode = QuicTransportErrorCode.StreamStateError;
            return false;
        }

        errorCode = default;
        return true;
    }

    private bool FailWriteAfterRollback(
        TaskCompletionSource<object?> completion,
        QuicConnectionStreamSendStateSnapshot sendStateBeforeWrite,
        Exception exception)
    {
        if (!streamRegistry.Bookkeeping.TryRestoreSendState(sendStateBeforeWrite))
        {
            completion.TrySetException(new InvalidOperationException(
                "The connection runtime could not roll back the failed stream write.",
                exception));
            return false;
        }

        completion.TrySetException(exception);
        return false;
    }

    private bool ShouldDelayApplicationSend(ReadOnlySpan<byte> streamData)
    {
        return (activePath?.AmplificationState.IsAddressValidated ?? false)
            && streamData.Length > 0
            && (applicationSendQueue.Count > 0
                || streamData.Length < ApplicationSendDelayThresholdBytes);
    }

    private void QueuePendingApplicationSend(
        ulong streamId,
        int priority,
        byte[] streamPayload,
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        applicationSendQueue.Enqueue(streamId, priority, streamPayload);

        if (applicationSendQueue.Count == 1)
        {
            pendingApplicationSendDelayDueTicks = SaturatingAdd(
                nowTicks,
                ConvertMicrosToTicks(ApplicationSendDelayMicros));
        }

        AppendEffects(ref effects, RecomputeLifecycleTimerEffects());
    }

    private bool TryPromoteQueuedApplicationSendToFinal(ulong streamId)
    {
        if (!applicationSendQueue.TryGetLatestQueuedWriteForStream(streamId, out PendingApplicationSendRequest queuedWrite))
        {
            return false;
        }

        if (!QuicStreamParser.TryParseStreamFrame(queuedWrite.StreamPayload, out QuicStreamFrame frame)
            || !TryBuildOutboundStreamPayload(
                streamId,
                frame.Offset,
                frame.StreamData,
                fin: true,
                out byte[] finalPayload))
        {
            return false;
        }

        return applicationSendQueue.TryReplaceQueuedWritePayload(queuedWrite.Sequence, finalPayload);
    }

    private bool FlushPendingApplicationSends(long nowTicks, ref List<QuicConnectionEffect>? effects)
        => FlushPendingApplicationSends(nowTicks, ref effects, out _);

    private bool FlushPendingApplicationSends(
        long nowTicks,
        ref List<QuicConnectionEffect>? effects,
        out Exception? exception)
        => FlushPendingApplicationSends(nowTicks, probePacket: false, ref effects, out exception);

    private bool FlushPendingApplicationSends(
        long nowTicks,
        bool probePacket,
        ref List<QuicConnectionEffect>? effects)
        => FlushPendingApplicationSends(nowTicks, probePacket, ref effects, out _);

    private bool FlushPendingApplicationSends(
        long nowTicks,
        bool probePacket,
        ref List<QuicConnectionEffect>? effects,
        out Exception? exception)
    {
        if (applicationSendQueue.Count == 0)
        {
            pendingApplicationSendDelayDueTicks = null;
            exception = null;
            return false;
        }

        PendingApplicationSendRequest[] queuedWrites = applicationSendQueue.GetSortedQueuedWrites();

        int batchCount = QuicApplicationSendQueue.SelectQueuedApplicationSendBatchCount(
            queuedWrites,
            GetMaximumQueuedApplicationPayloadBytes());
        ReadOnlySpan<PendingApplicationSendRequest> selectedWrites = queuedWrites.AsSpan(0, batchCount);
        int combinedPayloadLength = 0;
        foreach (PendingApplicationSendRequest queuedWrite in selectedWrites)
        {
            combinedPayloadLength = checked(combinedPayloadLength + queuedWrite.StreamPayload.Length);
        }

        byte[] combinedPayload = new byte[combinedPayloadLength];
        int copyOffset = 0;
        foreach (PendingApplicationSendRequest queuedWrite in selectedWrites)
        {
            queuedWrite.StreamPayload.CopyTo(combinedPayload.AsSpan(copyOffset));
            copyOffset += queuedWrite.StreamPayload.Length;
        }

        ulong[] streamIds = QuicApplicationSendQueue.BuildDistinctStreamIds(selectedWrites);

        if (!TryProtectAndAccountStreamApplicationPayload(
            combinedPayload,
            "The connection runtime could not protect the queued stream write packet.",
            QueuedStreamWriteSendBlockedMessage,
            probePacket,
            streamIds,
            ref effects,
            out QuicConnectionPathIdentity sendPathIdentity,
            out ReadOnlyMemory<byte> protectedPacket,
            out exception))
        {
            if (IsTransientApplicationSendPathBlocked(exception))
            {
                pendingApplicationSendDelayDueTicks = SaturatingAdd(
                    nowTicks,
                    ConvertMicrosToTicks(ApplicationSendDelayMicros));
                AppendEffects(ref effects, RecomputeLifecycleTimerEffects());
            }

            return false;
        }

        applicationSendQueue.TryRemoveQueuedWrites(selectedWrites);
        if (applicationSendQueue.Count == 0)
        {
            pendingApplicationSendDelayDueTicks = null;
        }
        else
        {
            pendingApplicationSendDelayDueTicks = SaturatingAdd(
                nowTicks,
                ConvertMicrosToTicks(ApplicationSendDelayMicros));
        }

        AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(
            sendPathIdentity,
            protectedPacket));
        AppendEffects(ref effects, RecomputeLifecycleTimerEffects());
        exception = null;
        return true;
    }

    private bool TryProtectAndAccountStreamApplicationPayload(
        ReadOnlyMemory<byte> payload,
        string protectFailureMessage,
        string amplificationFailureMessage,
        bool probePacket,
        ulong[]? streamIds,
        ref List<QuicConnectionEffect>? effects,
        out QuicConnectionPathIdentity sendPathIdentity,
        out ReadOnlyMemory<byte> protectedPacket,
        out Exception? exception)
    {
        sendPathIdentity = default;
        protectedPacket = ReadOnlyMemory<byte>.Empty;

        if (activePath is null)
        {
            exception = new InvalidOperationException("The connection has no active path.");
            return false;
        }

        QuicConnectionPathIdentity selectedPathIdentity = activePath.Value.Identity;
        if (!probePacket && TryGetPermittedPeerMigrationSendPath(out QuicConnectionPathIdentity peerMigrationPathIdentity))
        {
            selectedPathIdentity = peerMigrationPathIdentity;
        }

        return TryProtectAndAccountApplicationPayloadOnPath(
            selectedPathIdentity,
            payload,
            protectFailureMessage,
            amplificationFailureMessage,
            ref effects,
            out sendPathIdentity,
            out protectedPacket,
            out exception,
            retransmittable: true,
            probePacket: probePacket,
            includeAckFrame: true,
            streamIds: streamIds);
    }

    private bool TryFlushPendingApplicationSendsAfterRecoveryProgress(
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        if (sendRuntime.HasPendingRetransmission(QuicPacketNumberSpace.ApplicationData))
        {
            return false;
        }

        bool stateChanged = false;
        while (applicationSendQueue.Count > 0)
        {
            if (!FlushPendingApplicationSends(nowTicks, ref effects))
            {
                break;
            }

            stateChanged = true;
            if (sendRuntime.HasPendingRetransmission(QuicPacketNumberSpace.ApplicationData))
            {
                break;
            }
        }

        return stateChanged;
    }

    private static bool IsTransientCongestionExhaustion(Exception? exception)
    {
        return exception is InvalidOperationException invalidOperationException
            && string.Equals(
                invalidOperationException.Message,
                CongestionControllerExhaustedMessage,
                StringComparison.Ordinal);
    }

    private static bool IsTransientApplicationSendPathBlocked(Exception? exception)
    {
        return IsTransientCongestionExhaustion(exception)
            || exception is InvalidOperationException invalidOperationException
            && (string.Equals(
                    invalidOperationException.Message,
                    StreamWriteSendBlockedMessage,
                    StringComparison.Ordinal)
                || string.Equals(
                    invalidOperationException.Message,
                    QueuedStreamWriteSendBlockedMessage,
                    StringComparison.Ordinal));
    }

    private void TryRemoveQueuedApplicationSendsForStream(ulong streamId, ref List<QuicConnectionEffect>? effects)
    {
        if (!applicationSendQueue.TryRemoveQueuedWritesForStream(streamId))
        {
            return;
        }

        if (applicationSendQueue.Count == 0)
        {
            pendingApplicationSendDelayDueTicks = null;
            AppendEffects(ref effects, RecomputeLifecycleTimerEffects());
        }
    }

    private int GetMaximumQueuedApplicationPayloadBytes()
    {
        if (!activePath.HasValue)
        {
            return int.MaxValue;
        }

        ulong maximumDatagramSizeBytes = activePath.Value.MaximumDatagramSizeState.MaximumDatagramSizeBytes;
        int shortHeaderOverheadBytes =
            1
            + CurrentPeerDestinationConnectionId.Length
            + ApplicationPacketNumberLengthBytes
            + QuicInitialPacketProtection.AuthenticationTagLength;
        ulong reservedBytes = (ulong)(shortHeaderOverheadBytes + ApplicationSendBatchAckHeadroomBytes);
        if (maximumDatagramSizeBytes <= reservedBytes)
        {
            return ApplicationMinimumProtectedPayloadLength;
        }

        ulong maximumPayloadBytes = maximumDatagramSizeBytes - reservedBytes;
        return maximumPayloadBytes > int.MaxValue
            ? int.MaxValue
            : Math.Max(ApplicationMinimumProtectedPayloadLength, (int)maximumPayloadBytes);
    }

    private bool TryEmitFlowControlBlockedSignal(
        QuicDataBlockedFrame dataBlockedFrame,
        QuicStreamDataBlockedFrame streamDataBlockedFrame,
        ref List<QuicConnectionEffect>? effects)
    {
        if (sendRuntime.HasAckElicitingPacketsInFlight || sendRuntime.PendingRetransmissionCount > 0)
        {
            return false;
        }

        if (dataBlockedFrame.MaximumData != 0)
        {
            QuicMetrics.RecordFlowControlBlocked(tlsState.Role);
            EmitDiagnostic(ref effects, QuicDiagnostics.FlowControlBlocked(dataBlockedFrame));
            return TrySendFlowControlBlockedSignal(
                dataBlockedFrame,
                "The connection runtime could not protect the data-blocked packet.",
                "The connection cannot send the data-blocked packet.",
                ref effects);
        }

        if (streamDataBlockedFrame.MaximumStreamData != 0)
        {
            QuicMetrics.RecordFlowControlBlocked(tlsState.Role);
            EmitDiagnostic(ref effects, QuicDiagnostics.FlowControlBlocked(streamDataBlockedFrame));
            return TrySendFlowControlBlockedSignal(
                streamDataBlockedFrame,
                "The connection runtime could not protect the stream-data-blocked packet.",
                "The connection cannot send the stream-data-blocked packet.",
                ref effects);
        }

        return false;
    }

    private bool TryEmitStreamsBlockedSignal(
        QuicStreamsBlockedFrame streamsBlockedFrame,
        ref List<QuicConnectionEffect>? effects)
    {
        if (sendRuntime.HasAckElicitingPacketsInFlight || sendRuntime.PendingRetransmissionCount > 0)
        {
            return false;
        }

        QuicMetrics.RecordStreamLimitBlocked(tlsState.Role, streamsBlockedFrame.IsBidirectional);
        EmitDiagnostic(ref effects, QuicDiagnostics.StreamLimitBlocked(streamsBlockedFrame));
        return TrySendStreamsBlockedSignal(
            streamsBlockedFrame,
            "The connection runtime could not protect the streams-blocked packet.",
            "The connection cannot send the streams-blocked packet.",
            ref effects);
    }

    private bool TryEmitFlowControlCreditUpdate(
        QuicMaxDataFrame? maxDataFrame,
        QuicMaxStreamDataFrame? maxStreamDataFrame,
        ref List<QuicConnectionEffect>? effects)
    {
        bool stateChanged = false;

        if (maxDataFrame.HasValue)
        {
            stateChanged |= TrySendFlowControlCreditUpdate(
                maxDataFrame.Value,
                "The connection runtime could not protect the MAX_DATA packet.",
                "The connection cannot send the MAX_DATA packet.",
                ref effects);
        }

        if (maxStreamDataFrame.HasValue)
        {
            stateChanged |= TrySendFlowControlCreditUpdate(
                maxStreamDataFrame.Value,
                "The connection runtime could not protect the MAX_STREAM_DATA packet.",
                "The connection cannot send the MAX_STREAM_DATA packet.",
                ref effects);
        }

        return stateChanged;
    }

    private bool TrySendFlowControlCreditUpdate(
        QuicMaxDataFrame frame,
        string protectFailureMessage,
        string amplificationFailureMessage,
        ref List<QuicConnectionEffect>? effects)
    {
        if (!TryBuildOutboundMaxDataPayload(frame, out byte[] payload))
        {
            return false;
        }

        if (!TryProtectAndAccountApplicationPayload(
            payload,
            protectFailureMessage,
            amplificationFailureMessage,
            ref effects,
            out QuicConnectionActivePathRecord currentPath,
            out QuicConnectionPathAmplificationState updatedAmplificationState,
            out ReadOnlyMemory<byte> protectedPacket,
            out Exception? exception))
        {
            _ = exception;
            return false;
        }

        activePath = currentPath with
        {
            AmplificationState = updatedAmplificationState,
        };

        AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(
            currentPath.Identity,
            protectedPacket));
        return true;
    }

    private bool TrySendFlowControlCreditUpdate(
        QuicMaxStreamDataFrame frame,
        string protectFailureMessage,
        string amplificationFailureMessage,
        ref List<QuicConnectionEffect>? effects)
    {
        if (!TryBuildOutboundMaxStreamDataPayload(frame, out byte[] payload))
        {
            return false;
        }

        if (!TryProtectAndAccountApplicationPayload(
            payload,
            protectFailureMessage,
            amplificationFailureMessage,
            ref effects,
            out QuicConnectionActivePathRecord currentPath,
            out QuicConnectionPathAmplificationState updatedAmplificationState,
            out ReadOnlyMemory<byte> protectedPacket,
            out Exception? exception))
        {
            _ = exception;
            return false;
        }

        activePath = currentPath with
        {
            AmplificationState = updatedAmplificationState,
        };

        AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(
            currentPath.Identity,
            protectedPacket));
        return true;
    }

    private bool TrySendFlowControlBlockedSignal(
        QuicDataBlockedFrame frame,
        string protectFailureMessage,
        string amplificationFailureMessage,
        ref List<QuicConnectionEffect>? effects)
    {
        if (!TryBuildOutboundDataBlockedPayload(frame, out byte[] blockedPayload))
        {
            return false;
        }

        if (!TryProtectAndAccountApplicationPayload(
            blockedPayload,
            protectFailureMessage,
            amplificationFailureMessage,
            ref effects,
            out QuicConnectionActivePathRecord currentPath,
            out QuicConnectionPathAmplificationState updatedAmplificationState,
            out ReadOnlyMemory<byte> protectedPacket,
            out Exception? exception))
        {
            _ = exception;
            return false;
        }

        activePath = currentPath with
        {
            AmplificationState = updatedAmplificationState,
        };

        AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(
            currentPath.Identity,
            protectedPacket));

        return true;
    }

    private bool TrySendFlowControlBlockedSignal(
        QuicStreamDataBlockedFrame frame,
        string protectFailureMessage,
        string amplificationFailureMessage,
        ref List<QuicConnectionEffect>? effects)
    {
        if (!TryBuildOutboundStreamDataBlockedPayload(frame, out byte[] blockedPayload))
        {
            return false;
        }

        if (!TryProtectAndAccountApplicationPayload(
            blockedPayload,
            protectFailureMessage,
            amplificationFailureMessage,
            ref effects,
            out QuicConnectionActivePathRecord currentPath,
            out QuicConnectionPathAmplificationState updatedAmplificationState,
            out ReadOnlyMemory<byte> protectedPacket,
            out Exception? exception))
        {
            _ = exception;
            return false;
        }

        activePath = currentPath with
        {
            AmplificationState = updatedAmplificationState,
        };

        AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(
            currentPath.Identity,
            protectedPacket));

        return true;
    }

    private bool TrySendStreamsBlockedSignal(
        QuicStreamsBlockedFrame frame,
        string protectFailureMessage,
        string amplificationFailureMessage,
        ref List<QuicConnectionEffect>? effects)
    {
        if (!TryBuildOutboundStreamsBlockedPayload(frame, out byte[] blockedPayload))
        {
            return false;
        }

        if (!TryProtectAndAccountApplicationPayload(
            blockedPayload,
            protectFailureMessage,
            amplificationFailureMessage,
            ref effects,
            out QuicConnectionActivePathRecord currentPath,
            out QuicConnectionPathAmplificationState updatedAmplificationState,
            out ReadOnlyMemory<byte> protectedPacket,
            out Exception? exception))
        {
            _ = exception;
            return false;
        }

        activePath = currentPath with
        {
            AmplificationState = updatedAmplificationState,
        };

        AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(
            currentPath.Identity,
            protectedPacket));

        return true;
    }

    private bool HandleResetStreamAction(
        long requestId,
        ulong streamId,
        ulong applicationErrorCode,
        ref List<QuicConnectionEffect>? effects)
    {
        if (!pendingStreamActionRequests.TryRemove(requestId, out TaskCompletionSource<object?>? completion))
        {
            return false;
        }

        if (!TryValidateStreamSendBoundary(out Exception? exception))
        {
            completion.TrySetException(exception!);
            return false;
        }

        if (!streamRegistry.Bookkeeping.TryAbortLocalStreamWrites(
            streamId,
            out ulong finalSize,
            out QuicTransportErrorCode errorCode))
        {
            completion.TrySetException(errorCode != default
                ? new QuicException(
                    QuicError.TransportError,
                    null,
                    (long)errorCode,
                    "The stream reset could not be committed.")
                : new InvalidOperationException("The writable side is already completed."));
            return false;
        }

        TryRemoveQueuedApplicationSendsForStream(streamId, ref effects);

        if (!TryBuildOutboundResetPayload(streamId, applicationErrorCode, finalSize, out byte[] streamPayload))
        {
            completion.TrySetException(new InvalidOperationException("The connection runtime could not build the stream reset payload."));
            return false;
        }

        if (!TryProtectAndAccountApplicationPayload(
            streamPayload,
            "The connection runtime could not protect the stream reset packet.",
            "The connection cannot send the stream reset packet.",
            ref effects,
            out QuicConnectionActivePathRecord currentPath,
            out QuicConnectionPathAmplificationState updatedAmplificationState,
            out ReadOnlyMemory<byte> protectedPacket,
            out exception))
        {
            completion.TrySetException(exception!);
            return false;
        }

        activePath = currentPath with
        {
            AmplificationState = updatedAmplificationState,
        };

        AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(
            currentPath.Identity,
            protectedPacket));

        TryReleasePeerStreamCapacity(streamId, ref effects);
        _ = sendRuntime.TrySuppressRetransmissionForStream(streamId);
        NotifyStreamObservers(
            streamId,
            new QuicStreamNotification(
                QuicStreamNotificationKind.WriteAborted,
                CreateLocalOperationAbortedException("The local write side was aborted.")));

        completion.TrySetResult(null);
        return true;
    }

    private bool HandleStopSendingStreamAction(
        long requestId,
        ulong streamId,
        ulong applicationErrorCode,
        ref List<QuicConnectionEffect>? effects)
    {
        if (!pendingStreamActionRequests.TryRemove(requestId, out TaskCompletionSource<object?>? completion))
        {
            return false;
        }

        if (!TryValidateStreamSendBoundary(out Exception? exception))
        {
            completion.TrySetException(exception!);
            return false;
        }

        if (streamRegistry.Bookkeeping.TryGetStreamSnapshot(streamId, out QuicConnectionStreamSnapshot snapshot)
            && snapshot.ReceiveState is QuicStreamReceiveState.ResetRecvd or QuicStreamReceiveState.ResetRead)
        {
            completion.TrySetResult(null);
            return true;
        }

        if (!TryBuildOutboundStopSendingPayload(streamId, applicationErrorCode, out byte[] streamPayload))
        {
            completion.TrySetException(new InvalidOperationException("The connection runtime could not build the stream stop-sending payload."));
            return false;
        }

        if (!TryProtectAndAccountApplicationPayload(
            streamPayload,
            "The connection runtime could not protect the stream stop-sending packet.",
            "The connection cannot send the stream stop-sending packet.",
            ref effects,
            out QuicConnectionActivePathRecord currentPath,
            out QuicConnectionPathAmplificationState updatedAmplificationState,
            out ReadOnlyMemory<byte> protectedPacket,
            out exception))
        {
            completion.TrySetException(exception!);
            return false;
        }

        activePath = currentPath with
        {
            AmplificationState = updatedAmplificationState,
        };

        AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(
            currentPath.Identity,
            protectedPacket));

        _ = streamRegistry.Bookkeeping.TryMarkLocalStopSendingFrameSent(streamId, out _);
        TryReleasePeerStreamCapacity(streamId, ref effects);
        _ = sendRuntime.TrySuppressRetransmissionForStream(streamId);
        NotifyStreamObservers(
            streamId,
            new QuicStreamNotification(
                QuicStreamNotificationKind.ReadAborted,
                CreateLocalOperationAbortedException("The local read side was aborted.")));

        completion.TrySetResult(null);
        return true;
    }

    private bool HandleReleaseCapacityStreamAction(
        ulong streamId,
        ref List<QuicConnectionEffect>? effects)
    {
        return TryReleasePeerStreamCapacity(streamId, ref effects);
    }

    private bool HandleFlowControlCreditUpdated(
        QuicConnectionFlowControlCreditUpdatedEvent flowControlCreditUpdatedEvent,
        ref List<QuicConnectionEffect>? effects)
    {
        return TryEmitFlowControlCreditUpdate(
            flowControlCreditUpdatedEvent.MaxDataFrame,
            flowControlCreditUpdatedEvent.MaxStreamDataFrame,
            ref effects);
    }

    private bool TryValidateStreamSendBoundary(out Exception? exception)
    {
        if (terminalState is QuicConnectionTerminalState terminalStateValue)
        {
            exception = CreateTerminalException(terminalStateValue);
            return false;
        }

        if (IsDisposed)
        {
            exception = new ObjectDisposedException(nameof(QuicConnectionRuntime));
            return false;
        }

        if (phase != QuicConnectionPhase.Active || activePath is null)
        {
            exception = new InvalidOperationException("The connection is not established.");
            return false;
        }

        if (!tlsState.OneRttKeysAvailable
            || !tlsState.OneRttProtectPacketProtectionMaterial.HasValue)
        {
            exception = new InvalidOperationException("The connection is not ready to send application stream data.");
            return false;
        }

        if (!activePath.Value.MaximumDatagramSizeState.CanSendOrdinaryPackets)
        {
            exception = new InvalidOperationException("The active path cannot send ordinary packets.");
            return false;
        }

        exception = null;
        return true;
    }

    private bool TryValidateDatagramSendBoundary(out Exception? exception)
    {
        if (!TryValidateStreamSendBoundary(out exception))
        {
            if (exception is InvalidOperationException invalidOperationException
                && string.Equals(
                    invalidOperationException.Message,
                    "The connection is not ready to send application stream data.",
                    StringComparison.Ordinal))
            {
                exception = new InvalidOperationException(
                    "The connection is not ready to send application DATAGRAM data.");
            }

            return false;
        }

        return true;
    }

    private bool TryReleasePeerStreamCapacity(ulong streamId, ref List<QuicConnectionEffect>? effects)
    {
        if (!TryValidateStreamSendBoundary(out Exception? exception))
        {
            _ = exception;
            return false;
        }

        if (!streamRegistry.Bookkeeping.TryPeekPeerStreamCapacityRelease(streamId, out QuicMaxStreamsFrame maxStreamsFrame))
        {
            return false;
        }

        if (!TryBuildOutboundMaxStreamsPayload(maxStreamsFrame, out byte[] streamPayload))
        {
            return false;
        }

        if (!TryProtectAndAccountApplicationPayload(
            streamPayload,
            "The connection runtime could not protect the stream capacity release packet.",
            "The connection cannot send the stream capacity release packet.",
            ref effects,
            out QuicConnectionActivePathRecord currentPath,
            out QuicConnectionPathAmplificationState updatedAmplificationState,
            out ReadOnlyMemory<byte> protectedPacket,
            out exception))
        {
            return false;
        }

        if (!streamRegistry.Bookkeeping.TryCommitPeerStreamCapacityRelease(streamId, maxStreamsFrame))
        {
            return false;
        }

        activePath = currentPath with
        {
            AmplificationState = updatedAmplificationState,
        };

        AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(
            currentPath.Identity,
            protectedPacket));

        return true;
    }

    private bool TrySendRetireConnectionIdFrame(
        ulong connectionId,
        ref List<QuicConnectionEffect>? effects)
    {
        if (!TryValidateStreamSendBoundary(out _))
        {
            return false;
        }

        if (!TryBuildOutboundRetireConnectionIdPayload(connectionId, out byte[] payload))
        {
            return false;
        }

        if (!TryProtectAndAccountApplicationPayload(
            payload,
            "The connection runtime could not protect the connection ID retirement packet.",
            "The connection cannot send the connection ID retirement packet.",
            ref effects,
            out QuicConnectionActivePathRecord currentPath,
            out QuicConnectionPathAmplificationState updatedAmplificationState,
            out ReadOnlyMemory<byte> protectedPacket,
            out Exception? exception))
        {
            _ = exception;
            return false;
        }

        activePath = currentPath with
        {
            AmplificationState = updatedAmplificationState,
        };

        AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(
            currentPath.Identity,
            protectedPacket));

        return true;
    }

    private bool TryProtectAndAccountApplicationPayload(
        ReadOnlyMemory<byte> payload,
        string protectFailureMessage,
        string amplificationFailureMessage,
        ref List<QuicConnectionEffect>? effects,
        out QuicConnectionActivePathRecord currentPath,
        out QuicConnectionPathAmplificationState updatedAmplificationState,
        out ReadOnlyMemory<byte> protectedPacket,
        out Exception? exception)
    {
        return TryProtectAndAccountApplicationPayload(
            payload,
            protectFailureMessage,
            amplificationFailureMessage,
            probePacket: false,
            ackOnlyPacket: false,
            streamIds: null,
            retainPlaintextPayload: true,
            ref effects,
            out currentPath,
            out updatedAmplificationState,
            out protectedPacket,
            out exception);
    }

    private bool TryProtectAndAccountApplicationPayload(
        ReadOnlyMemory<byte> payload,
        string protectFailureMessage,
        string amplificationFailureMessage,
        bool probePacket,
        bool ackOnlyPacket,
        ulong[]? streamIds,
        bool retainPlaintextPayload,
        ref List<QuicConnectionEffect>? effects,
        out QuicConnectionActivePathRecord currentPath,
        out QuicConnectionPathAmplificationState updatedAmplificationState,
        out ReadOnlyMemory<byte> protectedPacket,
        out Exception? exception)
    {
        currentPath = default;
        updatedAmplificationState = default;
        protectedPacket = ReadOnlyMemory<byte>.Empty;

        currentPath = activePath!.Value;
        if (!currentPath.MaximumDatagramSizeState.CanSendOrdinaryPackets)
        {
            exception = new InvalidOperationException("The active path cannot send ordinary packets.");
            return false;
        }

        if (!TryUsePeerDestinationConnectionIdOnPath(
                currentPath.Identity,
                retireInactivePathConnectionIds: false,
                ref effects,
                out exception))
        {
            return false;
        }

        if (!TryPrepareOneRttProtectionForAeadLimit(protectFailureMessage, ref effects, out exception))
        {
            return false;
        }

        if (TryHandlePacketNumberExhaustion(QuicPacketNumberSpace.ApplicationData, ref effects))
        {
            exception = terminalState is QuicConnectionTerminalState terminalStateValue
                ? CreateTerminalException(terminalStateValue)
                : new QuicException(
                    QuicError.TransportError,
                    null,
                    (long)QuicTransportErrorCode.ProtocolViolation,
                    "The connection reached the packet number exhaustion limit.");
            return false;
        }

        ulong nowMicros = GetElapsedMicros(lastTransitionTicks);
        ReadOnlyMemory<byte> packetPayload = payload;
        QuicAckFrame? piggybackedAckFrame = null;
        if (!ackOnlyPacket
            && QuicConnectionAckHelpers.TryBuildApplicationAckPiggybackPayload(
                payload,
                sendRuntime.FlowController,
                nowMicros,
                out byte[] piggybackedPayload,
                out QuicAckFrame includedAckFrame))
        {
            packetPayload = piggybackedPayload;
            piggybackedAckFrame = includedAckFrame;
        }

        if (!TryPreflightApplicationDataCongestionBudget(
                packetPayload.Length,
                ackOnlyPacket,
                probePacket,
                out exception))
        {
            return false;
        }

        QuicBufferLease protectedPacketLease = default;
        if (!handshakeFlowCoordinator.TryBuildProtectedApplicationDataPacketLease(
            packetPayload.Span,
            tlsState.OneRttProtectPacketProtectionMaterial!.Value,
            tlsState.CurrentOneRttKeyPhaseBit,
            currentPath.SpinBitState.StoredValue,
            PeerSupportsGreasedQuicBit,
            out ulong packetNumber,
            out protectedPacketLease))
        {
            exception = new InvalidOperationException(protectFailureMessage);
            return false;
        }

        byte[]? protectedPacketOwner = null;
        try
        {
            protectedPacketOwner = protectedPacketLease.TransferOwnership(out int protectedPacketLength);
            protectedPacket = protectedPacketOwner.AsMemory(0, protectedPacketLength);
        }
        finally
        {
            protectedPacketLease.Dispose();
        }

        if (!tlsState.TryRecordCurrentOneRttProtectionUse())
        {
            QuicBufferPool.ReturnBytes(protectedPacketOwner);
            exception = new InvalidOperationException(protectFailureMessage);
            return false;
        }

        if (!sendRuntime.FlowController.CanSend(
            QuicPacketNumberSpace.ApplicationData,
            (ulong)protectedPacket.Length,
            isAckOnlyPacket: ackOnlyPacket,
            isProbePacket: probePacket))
        {
            QuicBufferPool.ReturnBytes(protectedPacketOwner);
            exception = new InvalidOperationException(CongestionControllerExhaustedMessage);
            return false;
        }

        if (!currentPath.MaximumDatagramSizeState.CanSend((ulong)protectedPacket.Length))
        {
            QuicBufferPool.ReturnBytes(protectedPacketOwner);
            exception = new InvalidOperationException("The active path cannot send an ordinary packet.");
            return false;
        }

        if (!currentPath.AmplificationState.TryConsumeSendBudget(
            protectedPacket.Length,
            out updatedAmplificationState))
        {
            QuicBufferPool.ReturnBytes(protectedPacketOwner);
            exception = new InvalidOperationException(amplificationFailureMessage);
            return false;
        }

        TrackApplicationPacket(
            packetNumber,
            protectedPacket,
            ackEliciting: !ackOnlyPacket,
            ackOnlyPacket: ackOnlyPacket,
            retransmittable: !ackOnlyPacket,
            probePacket: probePacket,
            streamIds: streamIds,
            plaintextPayload: retainPlaintextPayload ? payload : default,
            packetBytesOwner: protectedPacketOwner);
        if (piggybackedAckFrame is not null)
        {
            MarkApplicationAckFrameSent(
                piggybackedAckFrame,
                packetNumber,
                sentAtMicros: nowMicros,
                ackOnlyPacket: false);
        }

        exception = null;
        return true;
    }

    private bool TryProtectAndAccountApplicationPayloadOnPath(
        QuicConnectionPathIdentity pathIdentity,
        ReadOnlyMemory<byte> payload,
        string protectFailureMessage,
        string amplificationFailureMessage,
        ref List<QuicConnectionEffect>? effects,
        out QuicConnectionPathIdentity sendPathIdentity,
        out ReadOnlyMemory<byte> protectedPacket,
        out Exception? exception,
        bool retransmittable = true,
        bool probePacket = false,
        bool includeAckFrame = true,
        ulong[]? streamIds = null,
        bool enforcePathMaximumDatagramSize = false)
    {
        sendPathIdentity = default;
        protectedPacket = ReadOnlyMemory<byte>.Empty;

        if (!tlsState.OneRttProtectPacketProtectionMaterial.HasValue)
        {
            exception = new InvalidOperationException(protectFailureMessage);
            return false;
        }
        if (!TryUsePeerDestinationConnectionIdOnPath(
                pathIdentity,
                retireInactivePathConnectionIds: false,
                ref effects,
                out exception))
        {
            return false;
        }

        if (!TryPrepareOneRttProtectionForAeadLimit(protectFailureMessage, ref effects, out exception))
        {
            return false;
        }

        QuicConnectionPathMaximumDatagramSizeState maximumDatagramSizeState = default;
        if (enforcePathMaximumDatagramSize
            && (!TryGetPathMaximumDatagramSizeState(
                    pathIdentity,
                    out maximumDatagramSizeState)
                || !maximumDatagramSizeState.CanSendOrdinaryPackets))
        {
            exception = new InvalidOperationException("The requested path cannot send ordinary packets.");
            return false;
        }

        if (TryHandlePacketNumberExhaustion(QuicPacketNumberSpace.ApplicationData, ref effects))
        {
            exception = terminalState is QuicConnectionTerminalState terminalStateValue
                ? CreateTerminalException(terminalStateValue)
                : new QuicException(
                    QuicError.TransportError,
                    null,
                    (long)QuicTransportErrorCode.ProtocolViolation,
                    "The connection reached the packet number exhaustion limit.");
            return false;
        }

        ulong nowMicros = GetElapsedMicros(lastTransitionTicks);
        ReadOnlyMemory<byte> packetPayload = payload;
        QuicAckFrame? piggybackedAckFrame = null;
        if (includeAckFrame
            && QuicConnectionAckHelpers.TryBuildApplicationAckPiggybackPayload(
                payload,
                sendRuntime.FlowController,
                nowMicros,
                out byte[] piggybackedPayload,
                out QuicAckFrame includedAckFrame))
        {
            packetPayload = piggybackedPayload;
            piggybackedAckFrame = includedAckFrame;
        }

        if (!TryPreflightApplicationDataCongestionBudget(
                packetPayload.Length,
                ackOnlyPacket: false,
                probePacket,
                out exception))
        {
            return false;
        }

        if (!TryGetStoredSpinBitForPath(pathIdentity, out bool pathSpinBit))
        {
            exception = new InvalidOperationException("The requested path is not available for an application packet.");
            return false;
        }

        QuicBufferLease protectedPacketLease = default;
        if (!handshakeFlowCoordinator.TryBuildProtectedApplicationDataPacketLease(
            packetPayload.Span,
            tlsState.OneRttProtectPacketProtectionMaterial!.Value,
            tlsState.CurrentOneRttKeyPhaseBit,
            pathSpinBit,
            PeerSupportsGreasedQuicBit,
            out ulong packetNumber,
            out protectedPacketLease))
        {
            exception = new InvalidOperationException(protectFailureMessage);
            return false;
        }

        byte[]? protectedPacketOwner = null;
        try
        {
            protectedPacketOwner = protectedPacketLease.TransferOwnership(out int protectedPacketLength);
            protectedPacket = protectedPacketOwner.AsMemory(0, protectedPacketLength);
        }
        finally
        {
            protectedPacketLease.Dispose();
        }

        if (!tlsState.TryRecordCurrentOneRttProtectionUse())
        {
            QuicBufferPool.ReturnBytes(protectedPacketOwner);
            exception = new InvalidOperationException(protectFailureMessage);
            return false;
        }

        if (!sendRuntime.FlowController.CanSend(
                QuicPacketNumberSpace.ApplicationData,
                (ulong)protectedPacket.Length,
                isProbePacket: probePacket))
        {
            QuicBufferPool.ReturnBytes(protectedPacketOwner);
            exception = new InvalidOperationException(CongestionControllerExhaustedMessage);
            return false;
        }

        if (enforcePathMaximumDatagramSize
            && !maximumDatagramSizeState.CanSend((ulong)protectedPacket.Length))
        {
            QuicBufferPool.ReturnBytes(protectedPacketOwner);
            exception = new InvalidOperationException("The requested path cannot send an ordinary packet.");
            return false;
        }

        if (activePath is not null
            && EqualityComparer<QuicConnectionPathIdentity>.Default.Equals(activePath.Value.Identity, pathIdentity))
        {
            QuicConnectionActivePathRecord currentPath = activePath.Value;
            if (!currentPath.AmplificationState.TryConsumeSendBudget(
                protectedPacket.Length,
                out QuicConnectionPathAmplificationState updatedAmplificationState))
            {
                QuicBufferPool.ReturnBytes(protectedPacketOwner);
                exception = new InvalidOperationException(amplificationFailureMessage);
                return false;
            }

            activePath = currentPath with
            {
                AmplificationState = updatedAmplificationState,
            };
        }
        else if (TryGetCandidatePath(pathIdentity, out QuicConnectionCandidatePathRecord candidatePath))
        {
            if (!candidatePath.AmplificationState.TryConsumeSendBudget(
                protectedPacket.Length,
                out QuicConnectionPathAmplificationState updatedAmplificationState))
            {
                QuicBufferPool.ReturnBytes(protectedPacketOwner);
                exception = new InvalidOperationException(amplificationFailureMessage);
                return false;
            }

            candidatePath = candidatePath with
            {
                AmplificationState = updatedAmplificationState,
            };
            candidatePaths[pathIdentity] = candidatePath;
        }
        else
        {
            QuicBufferPool.ReturnBytes(protectedPacketOwner);
            exception = new InvalidOperationException(amplificationFailureMessage);
            return false;
        }

        TrackApplicationPacket(
            packetNumber,
            protectedPacket,
            retransmittable: retransmittable,
            probePacket: probePacket,
            streamIds: streamIds,
            plaintextPayload: payload,
            packetBytesOwner: protectedPacketOwner);
        if (piggybackedAckFrame is not null)
        {
            MarkApplicationAckFrameSent(
                piggybackedAckFrame,
                packetNumber,
                sentAtMicros: nowMicros,
                ackOnlyPacket: false);
        }

        sendPathIdentity = pathIdentity;
        exception = null;
        return true;
    }

    private bool TryGetPathMaximumDatagramSizeState(
        QuicConnectionPathIdentity pathIdentity,
        out QuicConnectionPathMaximumDatagramSizeState maximumDatagramSizeState)
    {
        if (activePath is not null
            && EqualityComparer<QuicConnectionPathIdentity>.Default.Equals(activePath.Value.Identity, pathIdentity))
        {
            maximumDatagramSizeState = activePath.Value.MaximumDatagramSizeState;
            return true;
        }

        if (TryGetCandidatePath(pathIdentity, out QuicConnectionCandidatePathRecord candidatePath))
        {
            maximumDatagramSizeState = candidatePath.MaximumDatagramSizeState;
            return true;
        }

        maximumDatagramSizeState = default;
        return false;
    }

    private bool TryPreflightApplicationDataCongestionBudget(
        int packetPayloadLength,
        bool ackOnlyPacket,
        bool probePacket,
        out Exception? exception)
    {
        if (packetPayloadLength < 0)
        {
            exception = new InvalidOperationException(CongestionControllerExhaustedMessage);
            return false;
        }

        ulong estimatedProtectedPacketLength = EstimateProtectedApplicationDataPacketLength(packetPayloadLength);
        if (!sendRuntime.FlowController.CanSend(
                QuicPacketNumberSpace.ApplicationData,
                estimatedProtectedPacketLength,
                isAckOnlyPacket: ackOnlyPacket,
                isProbePacket: probePacket))
        {
            exception = new InvalidOperationException(CongestionControllerExhaustedMessage);
            return false;
        }

        exception = null;
        return true;
    }

    private ulong EstimateProtectedApplicationDataPacketLength(int packetPayloadLength)
    {
        return checked((ulong)(
            1
            + CurrentPeerDestinationConnectionId.Length
            + ApplicationPacketNumberLengthBytes
            + packetPayloadLength
            + QuicInitialPacketProtection.AuthenticationTagLength));
    }

    private bool TryUsePeerDestinationConnectionIdOnPath(
        QuicConnectionPathIdentity pathIdentity,
        bool retireInactivePathConnectionIds,
        ref List<QuicConnectionEffect>? effects,
        out Exception? exception)
    {
        exception = null;

        if (PeerRequestedZeroLengthConnectionId())
        {
            return true;
        }

        if (!peerConnectionIdState.TryUseDestinationConnectionIdOnPath(
                pathIdentity,
                GetLocalActiveConnectionIdLimit(),
                retireInactivePathConnectionIds,
                out QuicTransportErrorCode errorCode,
                out bool destinationConnectionIdChanged,
                out ulong[] retiredSequenceNumbers))
        {
            exception = errorCode == QuicTransportErrorCode.NoError
                ? new InvalidOperationException("No unused peer connection ID is available for the selected address pair.")
                : new QuicException(
                    QuicError.TransportError,
                    null,
                    (long)errorCode,
                    "The peer connection ID address-pair policy could not be applied.");
            return false;
        }

        if (destinationConnectionIdChanged
            && !TrySetHandshakeDestinationConnectionId(peerConnectionIdState.CurrentDestinationConnectionId.Span))
        {
            exception = new InvalidOperationException("The peer connection ID could not be installed for the selected address pair.");
            return false;
        }

        foreach (ulong retiredSequenceNumber in retiredSequenceNumbers)
        {
            _ = TrySendRetireConnectionIdFrame(retiredSequenceNumber, ref effects);
        }

        return true;
    }

    private bool TryRegisterDetectedLosses(long nowTicks)
    {
        ulong nowMicros = GetElapsedMicros(nowTicks);
        IReadOnlyList<QuicLostPacket> lostPackets = recoveryController.DetectLostPackets(
            nowMicros,
            out _,
            out _);

        bool stateChanged = false;
        foreach (QuicLostPacket lostPacket in lostPackets)
        {
            stateChanged |= sendRuntime.TryRegisterLoss(
                lostPacket.PacketNumberSpace,
                lostPacket.PacketNumber,
                handshakeConfirmed: HandshakeConfirmed);
        }

        return stateChanged;
    }

    internal bool TryFlushPendingRetransmissions(
        QuicPacketNumberSpace packetNumberSpace,
        long nowTicks,
        bool probePacket,
        ref List<QuicConnectionEffect>? effects)
    {
        if (activePath is null || sendRuntime.PendingRetransmissionCount == 0)
        {
            return false;
        }

        if (TryHandlePacketNumberExhaustion(packetNumberSpace, ref effects))
        {
            return true;
        }

        ulong sentAtMicros = GetElapsedMicros(nowTicks);
        if (probePacket)
        {
            if (!TryDequeuePreferredProbeRetransmission(
                    packetNumberSpace,
                    out QuicConnectionRetransmissionPlan probeRetransmission))
            {
                return false;
            }

            ReadOnlyMemory<byte> datagram = probeRetransmission.PacketBytes;
            bool rebuildableCryptoRetransmission = TryGetCryptoRetransmissionProtectionLevel(
                probeRetransmission,
                out QuicTlsEncryptionLevel cryptoProtectionLevel);
            ulong rebuiltPacketNumber = default;
            byte[] rebuiltDatagram = [];
            ReadOnlyMemory<byte> rebuiltApplicationPayload = default;
            bool rebuildableApplicationRetransmission =
                !rebuildableCryptoRetransmission
                && probeRetransmission.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData;
            bool hasPiggybackedAck = false;
            QuicAckFrame piggybackedAckFrame = new();
            if ((rebuildableCryptoRetransmission
                    && !TryBuildCryptoRetransmissionPacket(
                        probeRetransmission,
                        sentAtMicros,
                        out _,
                        out rebuiltPacketNumber,
                        out rebuiltDatagram,
                        out hasPiggybackedAck,
                        out piggybackedAckFrame))
                || (rebuildableApplicationRetransmission
                    && !TryBuildApplicationRetransmissionPacket(
                        probeRetransmission,
                        ref effects,
                        out rebuiltPacketNumber,
                        out rebuiltDatagram,
                        out rebuiltApplicationPayload)))
            {
                sendRuntime.QueueRetransmission(probeRetransmission);
                return false;
            }

            if (rebuildableCryptoRetransmission
                || rebuildableApplicationRetransmission)
            {
                datagram = rebuiltDatagram;
            }

            if (datagram.IsEmpty)
            {
                QuicConnectionSendRuntime.ReleaseRetransmissionPlanResources(probeRetransmission);
                return false;
            }

            if (!TryConsumeRetransmissionSendBudget(
                    probeRetransmission.PacketNumberSpace,
                    datagram.Length,
                    probePacket,
                    out QuicConnectionPathIdentity retransmissionPathIdentity))
            {
                sendRuntime.QueueRetransmission(probeRetransmission);
                return false;
            }

            if (rebuildableCryptoRetransmission)
            {
                TrackCryptoRetransmissionSent(
                    retransmissionPathIdentity,
                    cryptoProtectionLevel,
                    rebuiltPacketNumber,
                    rebuiltDatagram,
                    probePacket,
                    ref effects);
                MarkCryptoRetransmissionAckFrameSent(
                    cryptoProtectionLevel,
                    rebuiltPacketNumber,
                    hasPiggybackedAck,
                    piggybackedAckFrame,
                    sentAtMicros);
            }
            else if (rebuildableApplicationRetransmission)
            {
                TrackApplicationRetransmissionSent(
                    rebuiltPacketNumber,
                    rebuiltDatagram,
                    sentAtMicros,
                    probePacket,
                    probeRetransmission.StreamIds,
                    rebuiltApplicationPayload);
            }
            else
            {
                TrackRetransmissionPlanSent(
                    retransmissionPathIdentity,
                    probeRetransmission,
                    sentAtMicros,
                    probePacket,
                    ref effects);
            }

            if (rebuildableCryptoRetransmission || rebuildableApplicationRetransmission)
            {
                QuicConnectionSendRuntime.ReleaseRetransmissionPlanResources(probeRetransmission);
            }

            AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(
                retransmissionPathIdentity,
                datagram));
            return true;
        }

        bool sentAny = false;
        int remainingPlans = sendRuntime.PendingRetransmissionCount;

        while (remainingPlans-- > 0
            && sendRuntime.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan retransmission))
        {
            if (retransmission.PacketNumberSpace != packetNumberSpace)
            {
                sendRuntime.QueueRetransmission(retransmission);
                continue;
            }

            ReadOnlyMemory<byte> datagram = retransmission.PacketBytes;
            bool rebuildableCryptoRetransmission = TryGetCryptoRetransmissionProtectionLevel(
                retransmission,
                out QuicTlsEncryptionLevel cryptoProtectionLevel);
            ulong rebuiltPacketNumber = default;
            byte[] rebuiltDatagram = [];
            ReadOnlyMemory<byte> rebuiltApplicationPayload = default;
            bool rebuildableApplicationRetransmission =
                !rebuildableCryptoRetransmission
                && retransmission.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData;
            bool hasPiggybackedAck = false;
            QuicAckFrame piggybackedAckFrame = new();
            if ((rebuildableCryptoRetransmission
                    && !TryBuildCryptoRetransmissionPacket(
                        retransmission,
                        sentAtMicros,
                        out _,
                        out rebuiltPacketNumber,
                        out rebuiltDatagram,
                        out hasPiggybackedAck,
                        out piggybackedAckFrame))
                || (rebuildableApplicationRetransmission
                    && !TryBuildApplicationRetransmissionPacket(
                        retransmission,
                        ref effects,
                        out rebuiltPacketNumber,
                        out rebuiltDatagram,
                        out rebuiltApplicationPayload)))
            {
                sendRuntime.QueueRetransmission(retransmission);
                break;
            }

            if (rebuildableCryptoRetransmission
                || rebuildableApplicationRetransmission)
            {
                datagram = rebuiltDatagram;
            }

            if (datagram.IsEmpty)
            {
                QuicConnectionSendRuntime.ReleaseRetransmissionPlanResources(retransmission);
                continue;
            }

            if (!TryConsumeRetransmissionSendBudget(
                    retransmission.PacketNumberSpace,
                    datagram.Length,
                    probePacket,
                    out QuicConnectionPathIdentity retransmissionPathIdentity))
            {
                sendRuntime.QueueRetransmission(retransmission);
                break;
            }

            if (rebuildableCryptoRetransmission)
            {
                TrackCryptoRetransmissionSent(
                    retransmissionPathIdentity,
                    cryptoProtectionLevel,
                    rebuiltPacketNumber,
                    rebuiltDatagram,
                    probePacket,
                    ref effects);
                MarkCryptoRetransmissionAckFrameSent(
                    cryptoProtectionLevel,
                    rebuiltPacketNumber,
                    hasPiggybackedAck,
                    piggybackedAckFrame,
                    sentAtMicros);
            }
            else if (rebuildableApplicationRetransmission)
            {
                TrackApplicationRetransmissionSent(
                    rebuiltPacketNumber,
                    rebuiltDatagram,
                    sentAtMicros,
                    probePacket,
                    retransmission.StreamIds,
                    rebuiltApplicationPayload);
            }
            else
            {
                TrackRetransmissionPlanSent(
                    retransmissionPathIdentity,
                    retransmission,
                    sentAtMicros,
                    probePacket,
                    ref effects);
            }

            if (rebuildableCryptoRetransmission || rebuildableApplicationRetransmission)
            {
                QuicConnectionSendRuntime.ReleaseRetransmissionPlanResources(retransmission);
            }

            AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(
                retransmissionPathIdentity,
                datagram));
            sentAny = true;

            if (probePacket)
            {
                break;
            }
        }

        return sentAny;
    }

    private bool TryConsumeRetransmissionSendBudget(
        QuicPacketNumberSpace packetNumberSpace,
        int datagramLength,
        bool probePacket,
        out QuicConnectionPathIdentity pathIdentity)
    {
        pathIdentity = default;
        if (activePath is null)
        {
            return false;
        }

        QuicConnectionPathIdentity selectedPathIdentity = activePath.Value.Identity;
        if (packetNumberSpace is QuicPacketNumberSpace.Initial or QuicPacketNumberSpace.Handshake
            && TryGetMostRecentUnconfirmedServerCandidatePath(out QuicConnectionPathIdentity candidatePathIdentity))
        {
            selectedPathIdentity = candidatePathIdentity;
        }
        else if (packetNumberSpace == QuicPacketNumberSpace.ApplicationData
            && TryGetPermittedPeerMigrationSendPath(out QuicConnectionPathIdentity peerMigrationPathIdentity))
        {
            selectedPathIdentity = peerMigrationPathIdentity;
        }

        if (!sendRuntime.FlowController.CanSend(
                packetNumberSpace,
                (ulong)datagramLength,
                isAckOnlyPacket: false,
                isProbePacket: probePacket))
        {
            return false;
        }

        if (EqualityComparer<QuicConnectionPathIdentity>.Default.Equals(activePath.Value.Identity, selectedPathIdentity))
        {
            QuicConnectionActivePathRecord currentPath = activePath.Value;
            if (!currentPath.MaximumDatagramSizeState.CanSendOrdinaryPackets
                || !currentPath.MaximumDatagramSizeState.CanSend((ulong)datagramLength)
                || !currentPath.AmplificationState.TryConsumeSendBudget(
                    datagramLength,
                    out QuicConnectionPathAmplificationState updatedAmplificationState))
            {
                return false;
            }

            activePath = currentPath with
            {
                AmplificationState = updatedAmplificationState,
            };
            pathIdentity = currentPath.Identity;
            return true;
        }

        if (!TryGetCandidatePath(selectedPathIdentity, out QuicConnectionCandidatePathRecord candidatePath)
            || !candidatePath.MaximumDatagramSizeState.CanSendOrdinaryPackets
            || !candidatePath.MaximumDatagramSizeState.CanSend((ulong)datagramLength)
            || !candidatePath.AmplificationState.TryConsumeSendBudget(
                datagramLength,
                out QuicConnectionPathAmplificationState updatedCandidateAmplificationState))
        {
            return false;
        }

        candidatePaths[selectedPathIdentity] = candidatePath with
        {
            AmplificationState = updatedCandidateAmplificationState,
        };
        pathIdentity = candidatePath.Identity;
        return true;
    }

    internal bool TryDequeuePreferredProbeRetransmission(
        QuicPacketNumberSpace packetNumberSpace,
        out QuicConnectionRetransmissionPlan retransmission)
    {
        if (packetNumberSpace is QuicPacketNumberSpace.Initial or QuicPacketNumberSpace.Handshake)
        {
            return TryDequeuePreferredCryptoProbeRetransmission(packetNumberSpace, out retransmission);
        }

        if (packetNumberSpace != QuicPacketNumberSpace.ApplicationData)
        {
            return sendRuntime.TryDequeueRetransmission(packetNumberSpace, out retransmission);
        }

        retransmission = default;
        if (sendRuntime.PendingRetransmissionCount == 0)
        {
            return false;
        }

        int queuedPlanCount = sendRuntime.PendingRetransmissionCount;
        List<QuicConnectionRetransmissionPlan> queuedPlans = [];
        while (queuedPlanCount-- > 0
            && sendRuntime.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan candidatePlan))
        {
            queuedPlans.Add(candidatePlan);
        }

        int selectedIndex = -1;
        bool selectedProbePacket = false;
        bool selectedHasPreferredPayload = false;
        bool selectedCarriesStreamData = false;
        bool selectedClosesStream = false;
        ulong selectedStreamEndOffset = 0;

        for (int index = 0; index < queuedPlans.Count; index++)
        {
            QuicConnectionRetransmissionPlan candidatePlan = queuedPlans[index];
            if (candidatePlan.PacketNumberSpace != packetNumberSpace)
            {
                continue;
            }

            bool candidateProbePacket = candidatePlan.ProbePacket;
            bool candidateHasPreferredPayload = candidatePlan.StreamIds is { Length: > 0 };
            bool candidateCarriesStreamData = false;
            bool candidateClosesStream = false;
            ulong candidateStreamEndOffset = 0;
            if (candidateHasPreferredPayload)
            {
                _ = TryGetApplicationProbeSelectionPriority(
                    candidatePlan,
                    out candidateCarriesStreamData,
                    out candidateClosesStream,
                    out candidateStreamEndOffset);
            }

            if (selectedIndex >= 0)
            {
                bool samePayloadClass = selectedHasPreferredPayload == candidateHasPreferredPayload;
                bool preferCandidateForFreshness = selectedProbePacket
                    && !candidateProbePacket
                    && samePayloadClass;
                if (!selectedProbePacket && candidateProbePacket && samePayloadClass)
                {
                    continue;
                }

                if (!preferCandidateForFreshness)
                {
                    if (selectedHasPreferredPayload && !candidateHasPreferredPayload)
                    {
                        continue;
                    }

                    if (!selectedHasPreferredPayload && candidateHasPreferredPayload)
                    {
                        // Prefer application retransmissions that actually repair stream progress.
                    }
                    else
                    {
                        if (!IsPreferredApplicationProbeCandidate(
                                selectedCarriesStreamData,
                                selectedClosesStream,
                                selectedStreamEndOffset,
                                queuedPlans[selectedIndex].PacketNumber,
                                candidateCarriesStreamData,
                                candidateClosesStream,
                                candidateStreamEndOffset,
                                candidatePlan.PacketNumber))
                        {
                            continue;
                        }
                    }
                }
            }

            selectedIndex = index;
            selectedProbePacket = candidateProbePacket;
            selectedHasPreferredPayload = candidateHasPreferredPayload;
            selectedCarriesStreamData = candidateCarriesStreamData;
            selectedClosesStream = candidateClosesStream;
            selectedStreamEndOffset = candidateStreamEndOffset;
        }

        if (selectedIndex < 0)
        {
            foreach (QuicConnectionRetransmissionPlan queuedPlan in queuedPlans)
            {
                sendRuntime.QueueRetransmission(queuedPlan);
            }

            return false;
        }

        retransmission = queuedPlans[selectedIndex];
        for (int index = 0; index < queuedPlans.Count; index++)
        {
            if (index == selectedIndex)
            {
                continue;
            }

            sendRuntime.QueueRetransmission(queuedPlans[index]);
        }

        return true;
    }

    private bool TryDequeuePreferredCryptoProbeRetransmission(
        QuicPacketNumberSpace packetNumberSpace,
        out QuicConnectionRetransmissionPlan retransmission)
    {
        retransmission = default;
        if (sendRuntime.PendingRetransmissionCount == 0)
        {
            return false;
        }

        int queuedPlanCount = sendRuntime.PendingRetransmissionCount;
        List<QuicConnectionRetransmissionPlan> queuedPlans = [];
        while (queuedPlanCount-- > 0
            && sendRuntime.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan candidatePlan))
        {
            queuedPlans.Add(candidatePlan);
        }

        int selectedIndex = -1;
        bool selectedHasCryptoPriority = false;
        ulong selectedCryptoEndOffset = 0;
        bool selectedProbePacket = false;
        ulong selectedPacketNumber = 0;

        for (int index = 0; index < queuedPlans.Count; index++)
        {
            QuicConnectionRetransmissionPlan candidatePlan = queuedPlans[index];
            if (candidatePlan.PacketNumberSpace != packetNumberSpace)
            {
                continue;
            }

            bool candidateHasCryptoPriority = TryGetCryptoProbeSelectionPriority(
                candidatePlan,
                out ulong candidateCryptoEndOffset);

            if (selectedIndex >= 0)
            {
                if (selectedHasCryptoPriority && !candidateHasCryptoPriority)
                {
                    continue;
                }

                if (selectedHasCryptoPriority == candidateHasCryptoPriority)
                {
                    if (!selectedHasCryptoPriority)
                    {
                        continue;
                    }

                    if (candidateCryptoEndOffset < selectedCryptoEndOffset)
                    {
                        continue;
                    }

                    if (candidateCryptoEndOffset == selectedCryptoEndOffset)
                    {
                        if (!selectedProbePacket && candidatePlan.ProbePacket)
                        {
                            continue;
                        }

                        if (selectedProbePacket == candidatePlan.ProbePacket
                            && candidatePlan.PacketNumber <= selectedPacketNumber)
                        {
                            continue;
                        }
                    }
                }
            }

            selectedIndex = index;
            selectedHasCryptoPriority = candidateHasCryptoPriority;
            selectedCryptoEndOffset = candidateCryptoEndOffset;
            selectedProbePacket = candidatePlan.ProbePacket;
            selectedPacketNumber = candidatePlan.PacketNumber;
        }

        if (selectedIndex < 0)
        {
            foreach (QuicConnectionRetransmissionPlan queuedPlan in queuedPlans)
            {
                sendRuntime.QueueRetransmission(queuedPlan);
            }

            return false;
        }

        retransmission = queuedPlans[selectedIndex];
        for (int index = 0; index < queuedPlans.Count; index++)
        {
            if (index == selectedIndex)
            {
                continue;
            }

            sendRuntime.QueueRetransmission(queuedPlans[index]);
        }

        return true;
    }

    private bool TrySendCoalescedCryptoRecoveryProbeDatagram(
        QuicPacketNumberSpace firstPacketNumberSpace,
        QuicPacketNumberSpace secondPacketNumberSpace,
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        if (activePath is null
            || !IsInitialAndHandshakePair(firstPacketNumberSpace, secondPacketNumberSpace))
        {
            return false;
        }

        if (TryHandlePacketNumberExhaustion(firstPacketNumberSpace, ref effects))
        {
            return true;
        }

        bool initialDequeued = TryDequeuePreferredProbeRetransmission(
            QuicPacketNumberSpace.Initial,
            out QuicConnectionRetransmissionPlan initialRetransmission);
        if (!initialDequeued
            && TryPromoteOutstandingProbePacket(QuicPacketNumberSpace.Initial))
        {
            initialDequeued = TryDequeuePreferredProbeRetransmission(
                QuicPacketNumberSpace.Initial,
                out initialRetransmission);
        }

        if (!initialDequeued)
        {
            return false;
        }

        bool handshakeDequeued = TryDequeuePreferredProbeRetransmission(
            QuicPacketNumberSpace.Handshake,
            out QuicConnectionRetransmissionPlan handshakeRetransmission);
        if (!handshakeDequeued
            && TryPromoteOutstandingProbePacket(QuicPacketNumberSpace.Handshake))
        {
            handshakeDequeued = TryDequeuePreferredProbeRetransmission(
                QuicPacketNumberSpace.Handshake,
                out handshakeRetransmission);
        }

        if (!handshakeDequeued)
        {
            sendRuntime.QueueRetransmission(initialRetransmission);
            return false;
        }

        bool queueInitialForRetry = true;
        bool queueHandshakeForRetry = true;
        try
        {
            if (!TryGetCryptoRetransmissionProtectionLevel(
                    initialRetransmission,
                    out QuicTlsEncryptionLevel initialProtectionLevel)
                || initialProtectionLevel != QuicTlsEncryptionLevel.Initial
                || !TryGetCryptoRetransmissionProtectionLevel(
                    handshakeRetransmission,
                    out QuicTlsEncryptionLevel handshakeProtectionLevel)
                || handshakeProtectionLevel != QuicTlsEncryptionLevel.Handshake)
            {
                return false;
            }

            ReadOnlySpan<byte> initialDestinationConnectionIdOverride = TryResolveClientInitialProbeDestinationConnectionId(
                initialRetransmission,
                handshakeRetransmission,
                out byte[] probeDestinationConnectionId)
                ? probeDestinationConnectionId
                : ReadOnlySpan<byte>.Empty;
            ulong sentAtMicros = GetElapsedMicros(nowTicks);
            if (!TryBuildCryptoRetransmissionPacket(
                    initialRetransmission,
                    initialDestinationConnectionIdOverride,
                    sentAtMicros,
                    out _,
                    out ulong rebuiltInitialPacketNumber,
                    out byte[] rebuiltInitialPacketBytes,
                    out bool hasInitialPiggybackedAck,
                    out QuicAckFrame initialPiggybackedAckFrame)
                || !TryBuildCryptoRetransmissionPacket(
                    handshakeRetransmission,
                    sentAtMicros,
                    out _,
                    out ulong rebuiltHandshakePacketNumber,
                    out byte[] rebuiltHandshakePacketBytes,
                    out bool hasHandshakePiggybackedAck,
                    out QuicAckFrame handshakePiggybackedAckFrame))
            {
                return false;
            }

            ReadOnlyMemory<byte> initialPacketBytes = rebuiltInitialPacketBytes;
            int coalescedDatagramLength = checked(
                initialPacketBytes.Length + rebuiltHandshakePacketBytes.Length);
            QuicConnectionActivePathRecord currentPath = activePath.Value;
            if (!currentPath.MaximumDatagramSizeState.CanSendOrdinaryPackets
                || !currentPath.MaximumDatagramSizeState.CanSend((ulong)coalescedDatagramLength)
                || !sendRuntime.FlowController.CanSend(
                    QuicPacketNumberSpace.Initial,
                    (ulong)coalescedDatagramLength,
                    isAckOnlyPacket: false,
                    isProbePacket: true)
                || !currentPath.AmplificationState.TryConsumeSendBudget(
                    coalescedDatagramLength,
                    out QuicConnectionPathAmplificationState updatedAmplificationState))
            {
                return false;
            }

            byte[] coalescedDatagram = new byte[coalescedDatagramLength];
            initialPacketBytes.CopyTo(coalescedDatagram);
            rebuiltHandshakePacketBytes.CopyTo(coalescedDatagram.AsMemory(initialPacketBytes.Length));

            activePath = currentPath with
            {
                AmplificationState = updatedAmplificationState,
            };

            TrackCryptoRetransmissionSent(
                currentPath.Identity,
                QuicTlsEncryptionLevel.Initial,
                rebuiltInitialPacketNumber,
                rebuiltInitialPacketBytes,
                probePacket: true,
                ref effects);
            MarkCryptoRetransmissionAckFrameSent(
                QuicTlsEncryptionLevel.Initial,
                rebuiltInitialPacketNumber,
                hasInitialPiggybackedAck,
                initialPiggybackedAckFrame,
                sentAtMicros);
            TrackCryptoRetransmissionSent(
                currentPath.Identity,
                QuicTlsEncryptionLevel.Handshake,
                rebuiltHandshakePacketNumber,
                rebuiltHandshakePacketBytes,
                probePacket: true,
                ref effects);
            MarkCryptoRetransmissionAckFrameSent(
                QuicTlsEncryptionLevel.Handshake,
                rebuiltHandshakePacketNumber,
                hasHandshakePiggybackedAck,
                handshakePiggybackedAckFrame,
                sentAtMicros);

            AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(
                currentPath.Identity,
                coalescedDatagram));

            queueInitialForRetry = false;
            queueHandshakeForRetry = false;
            return true;
        }
        finally
        {
            if (queueInitialForRetry)
            {
                sendRuntime.QueueRetransmission(initialRetransmission);
            }
            else
            {
                QuicConnectionSendRuntime.ReleaseRetransmissionPlanResources(initialRetransmission);
            }

            if (queueHandshakeForRetry)
            {
                sendRuntime.QueueRetransmission(handshakeRetransmission);
            }
            else
            {
                QuicConnectionSendRuntime.ReleaseRetransmissionPlanResources(handshakeRetransmission);
            }
        }
    }

    internal bool TrySendCoalescedHandshakeAndApplicationRecoveryProbeDatagram(
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        if (activePath is null)
        {
            return false;
        }

        if (TryHandlePacketNumberExhaustion(QuicPacketNumberSpace.Handshake, ref effects)
            || TryHandlePacketNumberExhaustion(QuicPacketNumberSpace.ApplicationData, ref effects))
        {
            return true;
        }

        bool applicationDequeued = TryDequeuePreferredProbeRetransmission(
            QuicPacketNumberSpace.ApplicationData,
            out QuicConnectionRetransmissionPlan applicationRetransmission);
        if (!applicationDequeued
            && TryPromoteOutstandingProbePacket(QuicPacketNumberSpace.ApplicationData))
        {
            applicationDequeued = TryDequeuePreferredProbeRetransmission(
                QuicPacketNumberSpace.ApplicationData,
                out applicationRetransmission);
        }

        if (!applicationDequeued)
        {
            return false;
        }

        bool handshakeDequeued = sendRuntime.TryDequeueRetransmission(
            QuicPacketNumberSpace.Handshake,
            out QuicConnectionRetransmissionPlan handshakeRetransmission);
        if (!handshakeDequeued
            && TryPromoteOutstandingProbePacket(QuicPacketNumberSpace.Handshake))
        {
            handshakeDequeued = sendRuntime.TryDequeueRetransmission(
                QuicPacketNumberSpace.Handshake,
                out handshakeRetransmission);
        }

        if (!handshakeDequeued)
        {
            sendRuntime.QueueRetransmission(applicationRetransmission);
            return false;
        }

        bool queueHandshakeForRetry = true;
        bool queueApplicationForRetry = true;
        try
        {
            if (!TryUsePeerDestinationConnectionIdOnPath(
                    activePath.Value.Identity,
                    retireInactivePathConnectionIds: false,
                    ref effects,
                    out _))
            {
                return false;
            }

            ReadOnlySpan<byte> handshakeDestinationConnectionIdOverride =
                CurrentPeerDestinationConnectionId.IsEmpty
                    ? ReadOnlySpan<byte>.Empty
                    : CurrentPeerDestinationConnectionId.Span;
            ulong sentAtMicros = GetElapsedMicros(nowTicks);

            if (!TryGetCryptoRetransmissionProtectionLevel(
                    handshakeRetransmission,
                    out QuicTlsEncryptionLevel handshakeProtectionLevel)
                || handshakeProtectionLevel != QuicTlsEncryptionLevel.Handshake
                || !TryBuildHandshakeCryptoRetransmissionPacketWithDestinationOverride(
                    handshakeRetransmission,
                    handshakeDestinationConnectionIdOverride,
                    sentAtMicros,
                    out ulong rebuiltHandshakePacketNumber,
                    out byte[] rebuiltHandshakePacketBytes,
                    out bool hasHandshakePiggybackedAck,
                    out QuicAckFrame handshakePiggybackedAckFrame)
                || !TryBuildApplicationRetransmissionPacket(
                    applicationRetransmission,
                    ref effects,
                    out ulong rebuiltApplicationPacketNumber,
                    out byte[] rebuiltApplicationPacketBytes,
                    out ReadOnlyMemory<byte> rebuiltApplicationPayload))
            {
                return false;
            }

            int coalescedDatagramLength = checked(
                rebuiltHandshakePacketBytes.Length + rebuiltApplicationPacketBytes.Length);
            QuicConnectionActivePathRecord currentPath = activePath.Value;
            if (!currentPath.MaximumDatagramSizeState.CanSendOrdinaryPackets
                || !currentPath.MaximumDatagramSizeState.CanSend((ulong)coalescedDatagramLength)
                || !sendRuntime.FlowController.CanSend(
                    QuicPacketNumberSpace.Handshake,
                    (ulong)coalescedDatagramLength,
                    isAckOnlyPacket: false,
                    isProbePacket: true)
                || !currentPath.AmplificationState.TryConsumeSendBudget(
                    coalescedDatagramLength,
                    out QuicConnectionPathAmplificationState updatedAmplificationState))
            {
                return false;
            }

            byte[] coalescedDatagram = new byte[coalescedDatagramLength];
            rebuiltHandshakePacketBytes.AsSpan().CopyTo(coalescedDatagram);
            rebuiltApplicationPacketBytes.AsSpan().CopyTo(coalescedDatagram.AsSpan(rebuiltHandshakePacketBytes.Length));

            activePath = currentPath with
            {
                AmplificationState = updatedAmplificationState,
            };

            TrackCryptoRetransmissionSent(
                currentPath.Identity,
                QuicTlsEncryptionLevel.Handshake,
                rebuiltHandshakePacketNumber,
                rebuiltHandshakePacketBytes,
                probePacket: true,
                ref effects);
            MarkCryptoRetransmissionAckFrameSent(
                QuicTlsEncryptionLevel.Handshake,
                rebuiltHandshakePacketNumber,
                hasHandshakePiggybackedAck,
                handshakePiggybackedAckFrame,
                sentAtMicros);
            TrackApplicationRetransmissionSent(
                rebuiltApplicationPacketNumber,
                rebuiltApplicationPacketBytes,
                sentAtMicros,
                probePacket: true,
                applicationRetransmission.StreamIds,
                rebuiltApplicationPayload);

            AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(
                currentPath.Identity,
                coalescedDatagram));

            queueHandshakeForRetry = false;
            queueApplicationForRetry = false;
            return true;
        }
        finally
        {
            if (queueHandshakeForRetry)
            {
                sendRuntime.QueueRetransmission(handshakeRetransmission);
            }
            else
            {
                QuicConnectionSendRuntime.ReleaseRetransmissionPlanResources(handshakeRetransmission);
            }

            if (queueApplicationForRetry)
            {
                sendRuntime.QueueRetransmission(applicationRetransmission);
            }
            else
            {
                QuicConnectionSendRuntime.ReleaseRetransmissionPlanResources(applicationRetransmission);
            }
        }
    }

    private bool TryResolveClientInitialProbeDestinationConnectionId(
        QuicConnectionRetransmissionPlan initialRetransmission,
        QuicConnectionRetransmissionPlan handshakeRetransmission,
        out byte[] destinationConnectionId)
    {
        destinationConnectionId = [];

        if (tlsState.Role != QuicTlsRole.Client
            || !TryGetLongHeaderDestinationConnectionId(
                initialRetransmission.PacketBytes.Span,
                out byte[] initialDestinationConnectionId)
            || !TryGetLongHeaderDestinationConnectionId(
                handshakeRetransmission.PacketBytes.Span,
                out byte[] handshakeDestinationConnectionId)
            || initialDestinationConnectionId.AsSpan().SequenceEqual(handshakeDestinationConnectionId))
        {
            return false;
        }

        destinationConnectionId = handshakeDestinationConnectionId;
        return true;
    }

    private static bool TryGetLongHeaderDestinationConnectionId(
        ReadOnlySpan<byte> packetBytes,
        out byte[] destinationConnectionId)
    {
        destinationConnectionId = [];

        if (!QuicPacketParsing.TryParseLongHeaderFields(
                packetBytes,
                out _,
                out _,
                out ReadOnlySpan<byte> parsedDestinationConnectionId,
                out _,
                out _))
        {
            return false;
        }

        destinationConnectionId = parsedDestinationConnectionId.ToArray();
        return destinationConnectionId.Length > 0;
    }

    private bool TryBuildCryptoRetransmissionPacket(
        QuicConnectionRetransmissionPlan retransmission,
        ulong nowMicros,
        out QuicTlsEncryptionLevel packetProtectionLevel,
        out ulong packetNumber,
        out byte[] protectedPacket,
        out bool hasPiggybackedAck,
        out QuicAckFrame piggybackedAckFrame)
    {
        return TryBuildCryptoRetransmissionPacket(
            retransmission,
            ReadOnlySpan<byte>.Empty,
            nowMicros,
            out packetProtectionLevel,
            out packetNumber,
            out protectedPacket,
            out hasPiggybackedAck,
            out piggybackedAckFrame);
    }

    private bool TryBuildCryptoRetransmissionPacket(
        QuicConnectionRetransmissionPlan retransmission,
        ReadOnlySpan<byte> initialDestinationConnectionIdOverride,
        ulong nowMicros,
        out QuicTlsEncryptionLevel packetProtectionLevel,
        out ulong packetNumber,
        out byte[] protectedPacket,
        out bool hasPiggybackedAck,
        out QuicAckFrame piggybackedAckFrame)
    {
        packetNumber = default;
        protectedPacket = [];
        hasPiggybackedAck = false;
        piggybackedAckFrame = new();

        if (!TryGetCryptoRetransmissionProtectionLevel(retransmission, out packetProtectionLevel))
        {
            return false;
        }

        return packetProtectionLevel switch
        {
            QuicTlsEncryptionLevel.Initial => TryBuildInitialCryptoRetransmissionPacket(
                retransmission,
                initialDestinationConnectionIdOverride,
                nowMicros,
                out packetNumber,
                out protectedPacket,
                out hasPiggybackedAck,
                out piggybackedAckFrame),
            QuicTlsEncryptionLevel.Handshake => TryBuildHandshakeCryptoRetransmissionPacket(
                retransmission,
                nowMicros,
                out packetNumber,
                out protectedPacket,
                out hasPiggybackedAck,
                out piggybackedAckFrame),
            _ => false,
        };
    }

    private bool TryBuildInitialCryptoRetransmissionPacket(
        QuicConnectionRetransmissionPlan retransmission,
        ReadOnlySpan<byte> destinationConnectionIdOverride,
        ulong nowMicros,
        out ulong packetNumber,
        out byte[] protectedPacket,
        out bool hasPiggybackedAck,
        out QuicAckFrame piggybackedAckFrame)
    {
        packetNumber = default;
        protectedPacket = [];
        hasPiggybackedAck = false;
        piggybackedAckFrame = new();

        if (initialPacketProtection is null)
        {
            return false;
        }

        if (!handshakeFlowCoordinator.TryOpenOutboundInitialPacket(
                retransmission.PacketBytes.Span,
                initialPacketProtection,
                out byte[] openedPacket,
                out int payloadOffset,
                out int payloadLength))
        {
            return false;
        }

        if (!TryParseRetransmittableCryptoFrame(
                openedPacket.AsSpan(payloadOffset, payloadLength),
                out ulong cryptoOffset,
                out byte[] cryptoPayload))
        {
            return false;
        }

        if (!QuicPacketParser.TryParseLongHeader(retransmission.PacketBytes.Span, out QuicLongHeaderPacket longHeader))
        {
            return false;
        }

        if (!TryParseInitialRetryToken(longHeader.VersionSpecificData, out byte[] parsedRetryToken))
        {
            return false;
        }

        ReadOnlySpan<byte> destinationConnectionId = destinationConnectionIdOverride.IsEmpty
            ? longHeader.DestinationConnectionId
            : destinationConnectionIdOverride;
        hasPiggybackedAck = TryBuildLongHeaderAckPiggybackFramePayload(
            QuicPacketNumberSpace.Initial,
            nowMicros,
            out byte[] ackFramePayload,
            out piggybackedAckFrame);

        return handshakeFlowCoordinator.TryBuildProtectedInitialPacketForRetransmission(
            cryptoPayload,
            cryptoOffset,
            longHeader.DestinationConnectionId,
            destinationConnectionId,
            longHeader.SourceConnectionId,
            parsedRetryToken,
            ackFramePayload,
            initialPacketProtection,
            out packetNumber,
            out protectedPacket);
    }

    private bool TryBuildHandshakeCryptoRetransmissionPacket(
        QuicConnectionRetransmissionPlan retransmission,
        ulong nowMicros,
        out ulong packetNumber,
        out byte[] protectedPacket,
        out bool hasPiggybackedAck,
        out QuicAckFrame piggybackedAckFrame)
    {
        packetNumber = default;
        protectedPacket = [];
        hasPiggybackedAck = false;
        piggybackedAckFrame = new();

        if (!tlsState.TryGetHandshakeProtectPacketProtectionMaterial(out QuicTlsPacketProtectionMaterial handshakeMaterial))
        {
            return false;
        }

        if (!handshakeFlowCoordinator.TryOpenHandshakePacket(
                retransmission.PacketBytes.Span,
                handshakeMaterial,
                out byte[] openedPacket,
                out int payloadOffset,
                out int payloadLength))
        {
            return false;
        }

        if (!TryParseRetransmittableCryptoFrame(
                openedPacket.AsSpan(payloadOffset, payloadLength),
                out ulong cryptoOffset,
                out byte[] cryptoPayload))
        {
            return false;
        }

        if (!QuicPacketParser.TryParseLongHeader(retransmission.PacketBytes.Span, out QuicLongHeaderPacket longHeader))
        {
            return false;
        }

        hasPiggybackedAck = TryBuildLongHeaderAckPiggybackFramePayload(
            QuicPacketNumberSpace.Handshake,
            nowMicros,
            out byte[] ackFramePayload,
            out piggybackedAckFrame);

        return handshakeFlowCoordinator.TryBuildProtectedHandshakePacketForRetransmission(
            cryptoPayload,
            cryptoOffset,
            longHeader.DestinationConnectionId,
            longHeader.SourceConnectionId,
            ackFramePayload,
            handshakeMaterial,
            out packetNumber,
            out protectedPacket);
    }

    private static bool TryParseRetransmittableCryptoFrame(
        ReadOnlySpan<byte> payload,
        out ulong cryptoOffset,
        out byte[] cryptoPayload)
    {
        cryptoOffset = default;
        cryptoPayload = [];

        int offset = 0;
        while (offset < payload.Length)
        {
            ReadOnlySpan<byte> remaining = payload[offset..];

            if (QuicFrameCodec.TryParsePaddingFrame(remaining, out int paddingBytesConsumed))
            {
                offset += paddingBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParseAckFrame(remaining, out _, out int ackBytesConsumed))
            {
                offset += ackBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParsePingFrame(remaining, out int pingBytesConsumed))
            {
                offset += pingBytesConsumed;
                continue;
            }

            if (!QuicFrameCodec.TryParseCryptoFrame(
                    remaining,
                    out QuicCryptoFrame cryptoFrame,
                    out int cryptoBytesConsumed)
                || cryptoBytesConsumed <= 0)
            {
                return false;
            }

            cryptoOffset = cryptoFrame.Offset;
            cryptoPayload = cryptoFrame.CryptoData.ToArray();
            return cryptoPayload.Length > 0;
        }

        return false;
    }

    private bool TryGetCryptoProbeSelectionPriority(
        QuicConnectionSentPacket packet,
        out ulong cryptoEndOffset)
    {
        cryptoEndOffset = default;

        QuicTlsEncryptionLevel? packetProtectionLevel = packet.PacketProtectionLevel
            ?? packet.CryptoMetadata?.EncryptionLevel;
        if (packet.PacketBytes.IsEmpty
            || packetProtectionLevel is not (QuicTlsEncryptionLevel.Initial or QuicTlsEncryptionLevel.Handshake))
        {
            return false;
        }

        return TryGetCryptoProbeSelectionPriority(
            packet.PacketBytes,
            packetProtectionLevel.Value,
            out cryptoEndOffset);
    }

    private bool TryGetCryptoProbeSelectionPriority(
        QuicConnectionRetransmissionPlan retransmission,
        out ulong cryptoEndOffset)
    {
        cryptoEndOffset = default;

        if (!TryGetCryptoRetransmissionProtectionLevel(retransmission, out QuicTlsEncryptionLevel packetProtectionLevel))
        {
            return false;
        }

        return TryGetCryptoProbeSelectionPriority(
            retransmission.PacketBytes,
            packetProtectionLevel,
            out cryptoEndOffset);
    }

    private bool TryGetCryptoProbeSelectionPriority(
        ReadOnlyMemory<byte> packetBytes,
        QuicTlsEncryptionLevel packetProtectionLevel,
        out ulong cryptoEndOffset)
    {
        cryptoEndOffset = default;

        switch (packetProtectionLevel)
        {
            case QuicTlsEncryptionLevel.Initial:
                if (initialPacketProtection is null
                    || !handshakeFlowCoordinator.TryOpenOutboundInitialPacket(
                        packetBytes.Span,
                        initialPacketProtection,
                        out byte[] openedInitialPacket,
                        out int initialPayloadOffset,
                        out int initialPayloadLength))
                {
                    return false;
                }

                return TryParseCryptoProbeSelectionPriority(
                    openedInitialPacket.AsSpan(initialPayloadOffset, initialPayloadLength),
                    out cryptoEndOffset);
            case QuicTlsEncryptionLevel.Handshake:
                if (!tlsState.TryGetHandshakeProtectPacketProtectionMaterial(out QuicTlsPacketProtectionMaterial handshakeMaterial)
                    || !handshakeFlowCoordinator.TryOpenHandshakePacket(
                        packetBytes.Span,
                        handshakeMaterial,
                        out byte[] openedHandshakePacket,
                        out int handshakePayloadOffset,
                        out int handshakePayloadLength))
                {
                    return false;
                }

                return TryParseCryptoProbeSelectionPriority(
                    openedHandshakePacket.AsSpan(handshakePayloadOffset, handshakePayloadLength),
                    out cryptoEndOffset);
            default:
                return false;
        }
    }

    private static bool TryParseCryptoProbeSelectionPriority(
        ReadOnlySpan<byte> payload,
        out ulong cryptoEndOffset)
    {
        cryptoEndOffset = default;
        bool parsedCryptoFrame = false;

        int offset = 0;
        while (offset < payload.Length)
        {
            ReadOnlySpan<byte> remaining = payload[offset..];

            if (QuicFrameCodec.TryParsePaddingFrame(remaining, out int paddingBytesConsumed))
            {
                offset += paddingBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParseAckFrame(remaining, out _, out int ackBytesConsumed))
            {
                offset += ackBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParsePingFrame(remaining, out int pingBytesConsumed))
            {
                offset += pingBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParseCryptoFrame(
                    remaining,
                    out QuicCryptoFrame cryptoFrame,
                    out int cryptoBytesConsumed))
            {
                if (cryptoFrame.CryptoData.Length > 0)
                {
                    ulong frameEndOffset = SaturatingAdd(
                        cryptoFrame.Offset,
                        (ulong)cryptoFrame.CryptoData.Length);
                    cryptoEndOffset = parsedCryptoFrame
                        ? Math.Max(cryptoEndOffset, frameEndOffset)
                        : frameEndOffset;
                    parsedCryptoFrame = true;
                }

                offset += cryptoBytesConsumed;
                continue;
            }

            break;
        }

        return parsedCryptoFrame;
    }

    private static ulong SaturatingAdd(ulong left, ulong right)
    {
        ulong sum = left + right;
        return sum < left ? ulong.MaxValue : sum;
    }

    private static bool TryParseInitialRetryToken(
        ReadOnlySpan<byte> versionSpecificData,
        out byte[] retryToken)
    {
        retryToken = [];

        if (!QuicVariableLengthInteger.TryParse(versionSpecificData, out ulong tokenLength, out int tokenLengthBytes)
            || tokenLength > (ulong)(versionSpecificData.Length - tokenLengthBytes))
        {
            return false;
        }

        retryToken = versionSpecificData.Slice(tokenLengthBytes, (int)tokenLength).ToArray();
        return true;
    }

    private bool TryBuildApplicationRetransmissionPacket(
        QuicConnectionRetransmissionPlan retransmission,
        ref List<QuicConnectionEffect>? effects,
        out ulong packetNumber,
        out byte[] protectedPacket,
        out ReadOnlyMemory<byte> plaintextPayload)
    {
        protectedPacket = [];
        packetNumber = default;
        plaintextPayload = default;

        if (retransmission.PacketNumberSpace != QuicPacketNumberSpace.ApplicationData
            || !tlsState.OneRttProtectPacketProtectionMaterial.HasValue)
        {
            return false;
        }

        if (!retransmission.PlaintextPayload.IsEmpty)
        {
            plaintextPayload = retransmission.PlaintextPayload;
        }
        else
        {
            if (retransmission.PacketBytes.IsEmpty)
            {
                return false;
            }

            QuicHandshakeFlowCoordinator retransmissionOpenCoordinator = new(CurrentPeerDestinationConnectionId);
            QuicBufferLease openedPacket = default;
            try
            {
                if (!retransmissionOpenCoordinator.TryOpenProtectedApplicationDataPacketLease(
                        retransmission.PacketBytes.Span,
                        tlsState.OneRttProtectPacketProtectionMaterial.Value,
                        expectedPacketNumber: 0,
                        PeerSupportsGreasedQuicBit,
                        out openedPacket,
                        out int payloadOffset,
                        out int payloadLength,
                        out _))
                {
                    return false;
                }

                plaintextPayload = openedPacket.Memory.Slice(payloadOffset, payloadLength).ToArray();
            }
            finally
            {
                openedPacket.Dispose();
            }
        }

        ulong minimumPacketNumberExclusive = retransmission.PacketNumber;
        ulong? largestTrackedPacketNumber = sendRuntime.GetLargestTrackedPacketNumber(QuicPacketNumberSpace.ApplicationData);
        if (largestTrackedPacketNumber.HasValue)
        {
            minimumPacketNumberExclusive = Math.Max(
                minimumPacketNumberExclusive,
                largestTrackedPacketNumber.Value);
        }

        if (!TryPrepareOneRttProtectionForAeadLimit(
                "The connection runtime could not protect the retransmitted application packet.",
                ref effects,
                out _))
        {
            return false;
        }

        if (!handshakeFlowCoordinator.TryBuildProtectedApplicationDataPacketForRetransmission(
            plaintextPayload.Span,
            minimumPacketNumberExclusive,
            tlsState.OneRttProtectPacketProtectionMaterial.Value,
            tlsState.CurrentOneRttKeyPhaseBit,
            activePath?.SpinBitState.StoredValue ?? QuicConnectionPathSpinBitState.CreateInitial().StoredValue,
            out packetNumber,
            out protectedPacket))
        {
            return false;
        }

        return tlsState.TryRecordCurrentOneRttProtectionUse();
    }

    private bool TryBuildHandshakeCryptoRetransmissionPacketWithDestinationOverride(
        QuicConnectionRetransmissionPlan retransmission,
        ReadOnlySpan<byte> destinationConnectionIdOverride,
        ulong nowMicros,
        out ulong packetNumber,
        out byte[] protectedPacket,
        out bool hasPiggybackedAck,
        out QuicAckFrame piggybackedAckFrame)
    {
        packetNumber = default;
        protectedPacket = [];
        hasPiggybackedAck = false;
        piggybackedAckFrame = new();

        if (!tlsState.TryGetHandshakeProtectPacketProtectionMaterial(out QuicTlsPacketProtectionMaterial handshakeMaterial))
        {
            return false;
        }

        if (!handshakeFlowCoordinator.TryOpenHandshakePacket(
                retransmission.PacketBytes.Span,
                handshakeMaterial,
                out byte[] openedPacket,
                out int payloadOffset,
                out int payloadLength))
        {
            return false;
        }

        if (!TryParseRetransmittableCryptoFrame(
                openedPacket.AsSpan(payloadOffset, payloadLength),
                out ulong cryptoOffset,
                out byte[] cryptoPayload))
        {
            return false;
        }

        if (!QuicPacketParser.TryParseLongHeader(retransmission.PacketBytes.Span, out QuicLongHeaderPacket longHeader))
        {
            return false;
        }

        ReadOnlySpan<byte> destinationConnectionId = destinationConnectionIdOverride.IsEmpty
            ? longHeader.DestinationConnectionId
            : destinationConnectionIdOverride;
        hasPiggybackedAck = TryBuildLongHeaderAckPiggybackFramePayload(
            QuicPacketNumberSpace.Handshake,
            nowMicros,
            out byte[] ackFramePayload,
            out piggybackedAckFrame);

        return handshakeFlowCoordinator.TryBuildProtectedHandshakePacketForRetransmission(
            cryptoPayload,
            cryptoOffset,
            destinationConnectionId,
            longHeader.SourceConnectionId,
            ackFramePayload,
            handshakeMaterial,
            out packetNumber,
            out protectedPacket);
    }

    private void MarkCryptoRetransmissionAckFrameSent(
        QuicTlsEncryptionLevel packetProtectionLevel,
        ulong packetNumber,
        bool hasPiggybackedAck,
        QuicAckFrame piggybackedAckFrame,
        ulong sentAtMicros)
    {
        if (!hasPiggybackedAck)
        {
            return;
        }

        QuicPacketNumberSpace packetNumberSpace = packetProtectionLevel switch
        {
            QuicTlsEncryptionLevel.Initial => QuicPacketNumberSpace.Initial,
            QuicTlsEncryptionLevel.Handshake => QuicPacketNumberSpace.Handshake,
            _ => throw new InvalidOperationException($"Unsupported crypto retransmission ACK protection level {packetProtectionLevel}."),
        };
        sendRuntime.FlowController.MarkAckFrameSent(
            packetNumberSpace,
            packetNumber,
            piggybackedAckFrame,
            sentAtMicros,
            ackOnlyPacket: false);
    }

    private void TrackCryptoRetransmissionSent(
        QuicConnectionPathIdentity pathIdentity,
        QuicTlsEncryptionLevel packetProtectionLevel,
        ulong packetNumber,
        byte[] protectedPacket,
        bool probePacket,
        ref List<QuicConnectionEffect>? effects)
    {
        switch (packetProtectionLevel)
        {
            case QuicTlsEncryptionLevel.Initial:
                TrackInitialPacket(packetNumber, protectedPacket, probePacket);
                if (diagnosticsEnabled)
                {
                    EmitDiagnostic(ref effects, QuicDiagnostics.InitialPacketSent(pathIdentity, protectedPacket));
                }

                break;
            case QuicTlsEncryptionLevel.Handshake:
                TrackHandshakePacket(packetNumber, protectedPacket, probePacket);
                if (diagnosticsEnabled)
                {
                    EmitDiagnostic(ref effects, QuicDiagnostics.HandshakePacketSent(pathIdentity, protectedPacket));
                }

                break;
            default:
                throw new InvalidOperationException($"Unsupported crypto retransmission protection level {packetProtectionLevel}.");
        }
    }

    private void TrackApplicationRetransmissionSent(
        ulong packetNumber,
        byte[] protectedPacket,
        ulong sentAtMicros,
        bool probePacket,
        ulong[]? streamIds,
        ReadOnlyMemory<byte> plaintextPayload)
    {
        sendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber,
            (ulong)protectedPacket.Length,
            sentAtMicros,
            AckEliciting: true,
            AckOnlyPacket: false,
            ProbePacket: probePacket,
            Retransmittable: true,
            PacketBytes: protectedPacket,
            PacketProtectionLevel: QuicTlsEncryptionLevel.OneRtt,
            StreamIds: streamIds,
            PlaintextPayload: plaintextPayload,
            OneRttKeyPhase: tlsState.CurrentOneRttKeyPhase));
        recoveryController.RecordPacketSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber,
            sentAtMicros,
            isAckElicitingPacket: true,
            isProbePacket: probePacket,
            packetProtectionLevel: QuicTlsEncryptionLevel.OneRtt,
            oneRttKeyPhase: tlsState.CurrentOneRttKeyPhase);

        if (idleTimeoutState is not null)
        {
            idleTimeoutState.RecordAckElicitingPacketSent(sentAtMicros);
        }
    }

    private void TrackRetransmissionPlanSent(
        QuicConnectionPathIdentity pathIdentity,
        QuicConnectionRetransmissionPlan retransmission,
        ulong sentAtMicros,
        bool probePacket,
        ref List<QuicConnectionEffect>? effects)
    {
        QuicTlsEncryptionLevel packetProtectionLevel = retransmission.PacketProtectionLevel
            ?? retransmission.CryptoMetadata?.EncryptionLevel
            ?? QuicTlsEncryptionLevel.OneRtt;

        sendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            retransmission.PacketNumberSpace,
            retransmission.PacketNumber,
            retransmission.PayloadBytes,
            sentAtMicros,
            AckEliciting: true,
            AckOnlyPacket: false,
            ProbePacket: probePacket,
            Retransmittable: true,
            CryptoMetadata: retransmission.CryptoMetadata,
            PacketBytes: retransmission.PacketBytes,
            PacketProtectionLevel: retransmission.PacketProtectionLevel,
            StreamIds: retransmission.StreamIds,
            PlaintextPayload: retransmission.PlaintextPayload,
            PacketBytesOwner: retransmission.PacketBytesOwner,
            OneRttKeyPhase: retransmission.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData
                && packetProtectionLevel == QuicTlsEncryptionLevel.OneRtt
                ? tlsState.CurrentOneRttKeyPhase
                : null));
        recoveryController.RecordPacketSent(
            retransmission.PacketNumberSpace,
            retransmission.PacketNumber,
            sentAtMicros,
            isAckElicitingPacket: true,
            isProbePacket: probePacket,
            packetProtectionLevel: packetProtectionLevel,
            oneRttKeyPhase: retransmission.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData
                && packetProtectionLevel == QuicTlsEncryptionLevel.OneRtt
                ? tlsState.CurrentOneRttKeyPhase
                : null);

        if (idleTimeoutState is not null)
        {
            idleTimeoutState.RecordAckElicitingPacketSent(sentAtMicros);
        }

        if (diagnosticsEnabled)
        {
            switch (retransmission.PacketNumberSpace)
            {
                case QuicPacketNumberSpace.Initial:
                    EmitDiagnostic(ref effects, QuicDiagnostics.InitialPacketSent(pathIdentity, retransmission.PacketBytes.Span));
                    break;
                case QuicPacketNumberSpace.Handshake:
                    EmitDiagnostic(ref effects, QuicDiagnostics.HandshakePacketSent(pathIdentity, retransmission.PacketBytes.Span));
                    break;
            }
        }
    }

    private static bool IsInitialAndHandshakePair(
        QuicPacketNumberSpace firstPacketNumberSpace,
        QuicPacketNumberSpace secondPacketNumberSpace)
    {
        return (firstPacketNumberSpace == QuicPacketNumberSpace.Initial
                && secondPacketNumberSpace == QuicPacketNumberSpace.Handshake)
            || (firstPacketNumberSpace == QuicPacketNumberSpace.Handshake
                && secondPacketNumberSpace == QuicPacketNumberSpace.Initial);
    }

    private static bool TryGetCryptoRetransmissionProtectionLevel(
        QuicConnectionRetransmissionPlan retransmission,
        out QuicTlsEncryptionLevel packetProtectionLevel)
    {
        QuicTlsEncryptionLevel? actualProtectionLevel = retransmission.PacketProtectionLevel
            ?? retransmission.CryptoMetadata?.EncryptionLevel;
        if (retransmission.PacketBytes.IsEmpty
            || actualProtectionLevel is not (QuicTlsEncryptionLevel.Initial or QuicTlsEncryptionLevel.Handshake))
        {
            packetProtectionLevel = default;
            return false;
        }

        packetProtectionLevel = actualProtectionLevel.Value;
        return true;
    }

    internal bool TrySetActivePathMaximumDatagramSize(ulong maximumDatagramSizeBytes, bool isProvisional = false)
    {
        if (activePath is null)
        {
            return false;
        }

        QuicConnectionPathMaximumDatagramSizeState maximumDatagramSizeState = isProvisional
            ? activePath.Value.MaximumDatagramSizeState.WithProvisionalMaximumDatagramSize(maximumDatagramSizeBytes)
            : activePath.Value.MaximumDatagramSizeState.WithMaximumDatagramSize(maximumDatagramSizeBytes);

        QuicConnectionActivePathRecord updatedActivePath = activePath.Value with
        {
            MaximumDatagramSizeState = maximumDatagramSizeState,
        };

        activePath = updatedActivePath;
        SyncActivePathMaximumDatagramSize(updatedActivePath.MaximumDatagramSizeState);
        return true;
    }
    private bool TryBuildOutboundRetireConnectionIdPayload(ulong sequenceNumber, out byte[] payload)
    {
        payload = [];

        byte[] buffer = new byte[Math.Max(ApplicationMinimumProtectedPayloadLength, 64)];
        if (!QuicFrameCodec.TryFormatRetireConnectionIdFrame(
            new QuicRetireConnectionIdFrame(sequenceNumber),
            buffer,
            out int frameBytesWritten))
        {
            return false;
        }

        if (frameBytesWritten > buffer.Length)
        {
            return false;
        }

        if (frameBytesWritten < buffer.Length)
        {
            buffer.AsSpan(frameBytesWritten).Fill(0);
        }

        payload = buffer;
        return true;
    }

    private bool TryBuildOutboundNewConnectionIdPayload(QuicNewConnectionIdFrame frame, out byte[] payload)
    {
        payload = [];

        byte[] buffer = new byte[Math.Max(ApplicationMinimumProtectedPayloadLength, 64)];
        if (!QuicFrameCodec.TryFormatNewConnectionIdFrame(frame, buffer, out int frameBytesWritten))
        {
            return false;
        }

        if (frameBytesWritten > buffer.Length)
        {
            return false;
        }

        if (frameBytesWritten < buffer.Length)
        {
            buffer.AsSpan(frameBytesWritten).Fill(0);
        }

        payload = buffer;
        return true;
    }

    internal void TrackApplicationPacket(
        ulong packetNumber,
        ReadOnlyMemory<byte> protectedPacket,
        bool ackEliciting = true,
        bool ackOnlyPacket = false,
        bool retransmittable = true,
        bool probePacket = false,
        QuicTlsEncryptionLevel packetProtectionLevel = QuicTlsEncryptionLevel.OneRtt,
        ulong[]? streamIds = null,
        ReadOnlyMemory<byte> plaintextPayload = default,
        byte[]? packetBytesOwner = null)
    {
        sendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber,
            (ulong)protectedPacket.Length,
            GetElapsedMicros(lastTransitionTicks),
            AckEliciting: ackEliciting,
            AckOnlyPacket: ackOnlyPacket,
            ProbePacket: probePacket,
            Retransmittable: retransmittable,
            PacketBytes: protectedPacket,
            PacketProtectionLevel: packetProtectionLevel,
            StreamIds: streamIds,
            PlaintextPayload: plaintextPayload,
            PacketBytesOwner: packetBytesOwner,
            OneRttKeyPhase: packetProtectionLevel == QuicTlsEncryptionLevel.OneRtt
                ? tlsState.CurrentOneRttKeyPhase
                : null));
        recoveryController.RecordPacketSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber,
            GetElapsedMicros(lastTransitionTicks),
            isAckElicitingPacket: ackEliciting,
            isProbePacket: probePacket,
            packetProtectionLevel: packetProtectionLevel,
            oneRttKeyPhase: packetProtectionLevel == QuicTlsEncryptionLevel.OneRtt
                ? tlsState.CurrentOneRttKeyPhase
                : null);

        if (ackEliciting && idleTimeoutState is not null)
        {
            idleTimeoutState.RecordAckElicitingPacketSent(GetElapsedMicros(lastTransitionTicks));
        }
    }

    private void TrackInitialPacket(ulong packetNumber, byte[] protectedPacket, bool probePacket = false)
    {
        TrackCryptoPacket(
            QuicPacketNumberSpace.Initial,
            QuicTlsEncryptionLevel.Initial,
            packetNumber,
            protectedPacket,
            probePacket);
    }

    private void TrackHandshakePacket(ulong packetNumber, byte[] protectedPacket, bool probePacket = false)
    {
        TrackCryptoPacket(
            QuicPacketNumberSpace.Handshake,
            QuicTlsEncryptionLevel.Handshake,
            packetNumber,
            protectedPacket,
            probePacket);
    }

    private void TrackCryptoPacket(
        QuicPacketNumberSpace packetNumberSpace,
        QuicTlsEncryptionLevel encryptionLevel,
        ulong packetNumber,
        byte[] protectedPacket,
        bool probePacket = false)
    {
        sendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            packetNumberSpace,
            packetNumber,
            (ulong)protectedPacket.Length,
            GetElapsedMicros(lastTransitionTicks),
            ProbePacket: probePacket,
            CryptoMetadata: new QuicConnectionCryptoSendMetadata(encryptionLevel),
            PacketBytes: protectedPacket,
            PacketProtectionLevel: encryptionLevel));
        recoveryController.RecordPacketSent(
            packetNumberSpace,
            packetNumber,
            GetElapsedMicros(lastTransitionTicks),
            isAckElicitingPacket: true,
            isProbePacket: probePacket,
            packetProtectionLevel: encryptionLevel);

        if (idleTimeoutState is not null)
        {
            idleTimeoutState.RecordAckElicitingPacketSent(GetElapsedMicros(lastTransitionTicks));
        }
    }

    private bool TryBuildOutboundStreamPayload(
        ulong streamId,
        ulong offset,
        ReadOnlySpan<byte> streamData,
        bool fin,
        out byte[] payload)
    {
        payload = [];

        byte frameType = OutboundStreamControlFrameType;
        if (offset != 0)
        {
            frameType |= QuicStreamFrameBits.OffsetBitMask;
        }

        if (fin)
        {
            frameType |= QuicStreamFrameBits.FinBitMask;
        }

        if (!TryGetOutboundStreamFrameLength(frameType, streamId, offset, streamData.Length, out int frameLength))
        {
            return false;
        }

        int bufferLength = Math.Max(ApplicationMinimumProtectedPayloadLength, frameLength);
        byte[] buffer = new byte[bufferLength];
        if (!QuicFrameCodec.TryFormatStreamFrame(
            frameType,
            streamId,
            offset,
            streamData,
            buffer,
            out int frameBytesWritten))
        {
            return false;
        }

        if (frameBytesWritten > buffer.Length)
        {
            return false;
        }

        if (frameBytesWritten < buffer.Length)
        {
            buffer.AsSpan(frameBytesWritten).Fill(0);
        }

        payload = buffer;
        return true;
    }

    private static bool TryGetOutboundStreamFrameLength(
        byte frameType,
        ulong streamId,
        ulong offset,
        int streamDataLength,
        out int frameLength)
    {
        frameLength = default;
        if (streamDataLength < 0)
        {
            return false;
        }

        bool hasOffset = (frameType & QuicStreamFrameBits.OffsetBitMask) != 0;
        bool hasLength = (frameType & QuicStreamFrameBits.LengthBitMask) != 0;
        ulong streamDataLengthValue = checked((ulong)streamDataLength);
        if (offset > QuicVariableLengthInteger.MaxValue - streamDataLengthValue
            || !QuicVariableLengthInteger.TryGetEncodedLength(frameType, out int frameTypeLength)
            || !QuicVariableLengthInteger.TryGetEncodedLength(streamId, out int streamIdLength))
        {
            return false;
        }

        int length = checked(frameTypeLength + streamIdLength);
        if (hasOffset)
        {
            if (!QuicVariableLengthInteger.TryGetEncodedLength(offset, out int offsetLength))
            {
                return false;
            }

            length = checked(length + offsetLength);
        }

        if (hasLength)
        {
            if (!QuicVariableLengthInteger.TryGetEncodedLength(streamDataLengthValue, out int streamDataLengthFieldLength))
            {
                return false;
            }

            length = checked(length + streamDataLengthFieldLength);
        }

        frameLength = checked(length + streamDataLength);
        return true;
    }

    private static bool TryBuildOutboundDatagramPayload(
        ReadOnlyMemory<byte> datagramData,
        out byte[] payload)
    {
        payload = [];

        byte[] buffer = new byte[
            1
            + QuicVariableLengthInteger.MaxEncodedLength
            + datagramData.Length];
        QuicDatagramFrame frame = new()
        {
            FrameType = QuicFrameCodec.DatagramWithLengthFrameType,
            DatagramData = datagramData.ToArray(),
        };

        if (!QuicFrameCodec.TryFormatDatagramFrame(frame, buffer, out int bytesWritten))
        {
            return false;
        }

        payload = bytesWritten == buffer.Length
            ? buffer
            : buffer[..bytesWritten];
        return true;
    }

    private static byte[] PadApplicationPayloadForProtection(byte[] payload)
    {
        if (payload.Length >= ApplicationMinimumProtectedPayloadLength)
        {
            return payload;
        }

        byte[] paddedPayload = new byte[ApplicationMinimumProtectedPayloadLength];
        payload.CopyTo(paddedPayload, 0);
        return paddedPayload;
    }

    private bool TryBuildOutboundResetPayload(
        ulong streamId,
        ulong applicationErrorCode,
        ulong finalSize,
        out byte[] payload)
    {
        payload = [];

        byte[] buffer = new byte[Math.Max(ApplicationMinimumProtectedPayloadLength, 64)];
        if (!QuicFrameCodec.TryFormatResetStreamFrame(
            new QuicResetStreamFrame(streamId, applicationErrorCode, finalSize),
            buffer,
            out int frameBytesWritten))
        {
            return false;
        }

        if (frameBytesWritten > buffer.Length)
        {
            return false;
        }

        if (frameBytesWritten < buffer.Length)
        {
            buffer.AsSpan(frameBytesWritten).Fill(0);
        }

        payload = buffer;
        return true;
    }

    private bool TryBuildOutboundStopSendingPayload(
        ulong streamId,
        ulong applicationErrorCode,
        out byte[] payload)
    {
        payload = [];

        byte[] buffer = new byte[Math.Max(ApplicationMinimumProtectedPayloadLength, 64)];
        if (!QuicFrameCodec.TryFormatStopSendingFrame(
            new QuicStopSendingFrame(streamId, applicationErrorCode),
            buffer,
            out int frameBytesWritten))
        {
            return false;
        }

        if (frameBytesWritten > buffer.Length)
        {
            return false;
        }

        if (frameBytesWritten < buffer.Length)
        {
            buffer.AsSpan(frameBytesWritten).Fill(0);
        }

        payload = buffer;
        return true;
    }

    private bool TryBuildOutboundMaxDataPayload(
        QuicMaxDataFrame frame,
        out byte[] payload)
    {
        payload = [];

        byte[] buffer = new byte[Math.Max(ApplicationMinimumProtectedPayloadLength, 64)];
        if (!QuicFrameCodec.TryFormatMaxDataFrame(frame, buffer, out int frameBytesWritten))
        {
            return false;
        }

        if (frameBytesWritten > buffer.Length)
        {
            return false;
        }

        if (frameBytesWritten < buffer.Length)
        {
            buffer.AsSpan(frameBytesWritten).Fill(0);
        }

        payload = buffer;
        return true;
    }

    private bool TryBuildOutboundMaxStreamDataPayload(
        QuicMaxStreamDataFrame frame,
        out byte[] payload)
    {
        payload = [];

        byte[] buffer = new byte[Math.Max(ApplicationMinimumProtectedPayloadLength, 64)];
        if (!QuicFrameCodec.TryFormatMaxStreamDataFrame(frame, buffer, out int frameBytesWritten))
        {
            return false;
        }

        if (frameBytesWritten > buffer.Length)
        {
            return false;
        }

        if (frameBytesWritten < buffer.Length)
        {
            buffer.AsSpan(frameBytesWritten).Fill(0);
        }

        payload = buffer;
        return true;
    }

    private bool TryBuildOutboundDataBlockedPayload(
        QuicDataBlockedFrame frame,
        out byte[] payload)
    {
        payload = [];

        byte[] buffer = new byte[Math.Max(ApplicationMinimumProtectedPayloadLength, 64)];
        if (!QuicFrameCodec.TryFormatDataBlockedFrame(frame, buffer, out int frameBytesWritten))
        {
            return false;
        }

        if (frameBytesWritten > buffer.Length)
        {
            return false;
        }

        if (frameBytesWritten < buffer.Length)
        {
            buffer.AsSpan(frameBytesWritten).Fill(0);
        }

        payload = buffer;
        return true;
    }

    private bool TryBuildOutboundStreamDataBlockedPayload(
        QuicStreamDataBlockedFrame frame,
        out byte[] payload)
    {
        payload = [];

        byte[] buffer = new byte[Math.Max(ApplicationMinimumProtectedPayloadLength, 64)];
        if (!QuicFrameCodec.TryFormatStreamDataBlockedFrame(frame, buffer, out int frameBytesWritten))
        {
            return false;
        }

        if (frameBytesWritten > buffer.Length)
        {
            return false;
        }

        if (frameBytesWritten < buffer.Length)
        {
            buffer.AsSpan(frameBytesWritten).Fill(0);
        }

        payload = buffer;
        return true;
    }

    private bool TryBuildOutboundStreamsBlockedPayload(
        QuicStreamsBlockedFrame frame,
        out byte[] payload)
    {
        payload = [];

        byte[] buffer = new byte[Math.Max(ApplicationMinimumProtectedPayloadLength, 64)];
        if (!QuicFrameCodec.TryFormatStreamsBlockedFrame(frame, buffer, out int frameBytesWritten))
        {
            return false;
        }

        if (frameBytesWritten > buffer.Length)
        {
            return false;
        }

        if (frameBytesWritten < buffer.Length)
        {
            buffer.AsSpan(frameBytesWritten).Fill(0);
        }

        payload = buffer;
        return true;
    }

    private bool TryBuildOutboundMaxStreamsPayload(QuicMaxStreamsFrame frame, out byte[] payload)
    {
        payload = [];

        byte[] buffer = new byte[Math.Max(ApplicationMinimumProtectedPayloadLength, 64)];
        if (!QuicFrameCodec.TryFormatMaxStreamsFrame(frame, buffer, out int frameBytesWritten))
        {
            return false;
        }

        if (frameBytesWritten > buffer.Length)
        {
            return false;
        }

        if (frameBytesWritten < buffer.Length)
        {
            buffer.AsSpan(frameBytesWritten).Fill(0);
        }

        payload = buffer;
        return true;
    }

    internal bool TryBuildOutboundHandshakeDonePayload(out byte[] payload)
    {
        payload = [];

        byte[] buffer = new byte[1];
        if (!QuicFrameCodec.TryFormatHandshakeDoneFrame(default, buffer, out int frameBytesWritten)
            || frameBytesWritten != buffer.Length)
        {
            return false;
        }

        payload = buffer;
        return true;
    }

    internal bool TryBuildOutboundOneRttCryptoPayload(
        ReadOnlySpan<byte> cryptoData,
        ulong cryptoOffset,
        out byte[] payload)
    {
        payload = [];

        if (cryptoData.IsEmpty)
        {
            return false;
        }

        int bufferLength = Math.Max(ApplicationMinimumProtectedPayloadLength, cryptoData.Length + 32);
        byte[] buffer = new byte[bufferLength];
        if (!QuicFrameCodec.TryFormatCryptoFrame(
            new QuicCryptoFrame(cryptoOffset, cryptoData),
            buffer,
            out int frameBytesWritten))
        {
            return false;
        }

        if (frameBytesWritten < buffer.Length)
        {
            buffer.AsSpan(frameBytesWritten).Fill(0);
        }

        payload = buffer;
        return true;
    }

    internal bool TryBuildOutboundNewTokenPayload(ReadOnlySpan<byte> token, out byte[] payload)
    {
        payload = [];

        if (tlsState.Role != QuicTlsRole.Server || token.IsEmpty)
        {
            return false;
        }

        int bufferLength = Math.Max(ApplicationMinimumProtectedPayloadLength, token.Length + 32);
        byte[] buffer = new byte[bufferLength];
        if (!QuicFrameCodec.TryFormatNewTokenFrame(new QuicNewTokenFrame(token), buffer, out int frameBytesWritten))
        {
            return false;
        }

        if (frameBytesWritten < buffer.Length)
        {
            buffer.AsSpan(frameBytesWritten).Fill(0);
        }

        payload = buffer;
        return true;
    }

    private bool TryHandleResetStreamFrame(
        QuicResetStreamFrame resetStreamFrame,
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        if (!streamRegistry.Bookkeeping.TryReceiveResetStreamFrame(
            resetStreamFrame,
            out QuicMaxDataFrame maxDataFrame,
            out QuicTransportErrorCode errorCode,
            suppressResetSignalWhenDataRecvd: true))
        {
            return TryHandleApplicationDataFrameError(
                nowTicks,
                QuicPacketFrameLegality.HandshakePacketResetStreamFrameType,
                errorCode,
                "The peer sent a RESET_STREAM frame that violated receive-side stream or flow-control state.",
                ref effects);
        }

        if (maxDataFrame.MaximumData != 0)
        {
            _ = TryEmitFlowControlCreditUpdate(maxDataFrame, default, ref effects);
        }

        if (streamRegistry.Bookkeeping.TryGetStreamSnapshot(resetStreamFrame.StreamId, out QuicConnectionStreamSnapshot snapshot)
            && snapshot.ReceiveState == QuicStreamReceiveState.ResetRecvd)
        {
            _ = sendRuntime.TrySuppressStopSendingRetransmissionForStream(resetStreamFrame.StreamId);
            if (snapshot.HasReceiveAbortErrorCode)
            {
                NotifyStreamObservers(
                    resetStreamFrame.StreamId,
                    new QuicStreamNotification(
                        QuicStreamNotificationKind.ReadAborted,
                        CreateStreamReadAbortedException(snapshot.ReceiveAbortErrorCode)));
            }

            _ = streamRegistry.Bookkeeping.TryAcknowledgeReset(resetStreamFrame.StreamId);
            TryReleasePeerStreamCapacity(resetStreamFrame.StreamId, ref effects);
        }

        return true;
    }

    private bool TryHandleStopSendingFrame(QuicStopSendingFrame stopSendingFrame, ref List<QuicConnectionEffect>? effects)
    {
        if (!streamRegistry.Bookkeeping.TryReceiveStopSendingFrame(
            stopSendingFrame,
            out QuicResetStreamFrame resetStreamFrame,
            out QuicTransportErrorCode errorCode))
        {
            _ = errorCode;
            return false;
        }

        if (!TryBuildOutboundResetPayload(
            resetStreamFrame.StreamId,
            resetStreamFrame.ApplicationProtocolErrorCode,
            resetStreamFrame.FinalSize,
            out byte[] streamPayload))
        {
            return false;
        }

        if (!TryProtectAndAccountApplicationPayload(
            streamPayload,
            "The connection runtime could not protect the stream reset packet.",
            "The connection cannot send the stream reset packet.",
            ref effects,
            out QuicConnectionActivePathRecord currentPath,
            out QuicConnectionPathAmplificationState updatedAmplificationState,
            out ReadOnlyMemory<byte> protectedPacket,
            out Exception? exception))
        {
            _ = exception;
            return false;
        }

        activePath = currentPath with
        {
            AmplificationState = updatedAmplificationState,
        };

        AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(
            currentPath.Identity,
            protectedPacket));

        NotifyStreamObservers(
            stopSendingFrame.StreamId,
            new QuicStreamNotification(
                QuicStreamNotificationKind.WriteAborted,
                CreateStreamWriteAbortedException(stopSendingFrame.ApplicationProtocolErrorCode)));

        TryReleasePeerStreamCapacity(stopSendingFrame.StreamId, ref effects);
        return true;
    }

    private void TryQueueInboundStreamId(ulong streamId)
    {
        if (!queuedInboundStreamIds.TryAdd(streamId, 0))
        {
            return;
        }

        if (ApplicationReceiveDebugEnabled)
        {
            Console.Error.WriteLine($"app-rx queue-inbound-stream role={tlsState.Role} stream={streamId}.");
        }

        _ = inboundStreamIds.Writer.TryWrite(streamId);
    }

    private bool IsPeerInitiatedInboundStreamId(ulong streamId)
    {
        QuicStreamId parsedStreamId = new(streamId);
        return tlsState.Role == QuicTlsRole.Server
            ? parsedStreamId.IsClientInitiated
            : parsedStreamId.IsServerInitiated;
    }

    private bool TryQueueInboundDatagram(ReadOnlyMemory<byte> datagram)
    {
        if (inboundDatagrams is null)
        {
            return false;
        }

        return inboundDatagrams.Writer.TryWrite(datagram.ToArray());
    }

    private void CompletePendingStreamOperations(Exception completionException)
    {
        CompleteInboundStreamQueue(completionException);
        CompleteInboundDatagramQueue(completionException);
        CompletePendingStreamOpenRequests(completionException);
        CompletePendingStreamActionRequests(completionException);
        CompletePendingDatagramSendRequests(completionException);
        applicationSendQueue.Clear();
        pendingApplicationSendDelayDueTicks = null;
    }

    private void CompleteInboundStreamQueue(Exception completionException)
    {
        inboundStreamQueueCompletionException ??= completionException;

        while (inboundStreamIds.Reader.TryRead(out _))
        {
            // Drain queued stream identifiers so pending accepts observe terminal completion.
        }

        inboundStreamIds.Writer.TryComplete(completionException);
    }

    private void CompleteInboundDatagramQueue(Exception completionException)
    {
        if (inboundDatagrams is null)
        {
            return;
        }

        inboundDatagramQueueCompletionException ??= completionException;

        while (inboundDatagrams.Reader.TryRead(out _))
        {
            // Drain queued DATAGRAM payloads so pending receives observe terminal completion.
        }

        inboundDatagrams.Writer.TryComplete(completionException);
    }

    private void CompletePendingStreamOpenRequests(Exception completionException)
    {
        if (pendingStreamOpenRequests.IsEmpty)
        {
            return;
        }

        foreach (KeyValuePair<long, TaskCompletionSource<ulong>> entry in pendingStreamOpenRequests.ToArray())
        {
            if (TryRemovePendingStreamOpenRequest(entry.Key, out TaskCompletionSource<ulong>? completion))
            {
                completion!.TrySetException(completionException);
            }
        }
    }

    private bool TryRemovePendingStreamOpenRequest(long requestId, out TaskCompletionSource<ulong>? completion)
    {
        if (!pendingStreamOpenRequests.TryRemove(requestId, out completion))
        {
            pendingStreamOpenTypes.TryRemove(requestId, out _);
            return false;
        }

        pendingStreamOpenTypes.TryRemove(requestId, out _);
        return true;
    }

    private void CompletePendingStreamActionRequests(Exception completionException)
    {
        if (pendingStreamActionRequests.IsEmpty)
        {
            return;
        }

        foreach (KeyValuePair<long, TaskCompletionSource<object?>> entry in pendingStreamActionRequests.ToArray())
        {
            if (pendingStreamActionRequests.TryRemove(entry.Key, out TaskCompletionSource<object?>? completion))
            {
                completion.TrySetException(completionException);
            }
        }
    }

    private void CompletePendingDatagramSendRequests(Exception completionException)
    {
        if (pendingDatagramSendRequests.IsEmpty)
        {
            return;
        }

        foreach (KeyValuePair<long, TaskCompletionSource<object?>> entry in pendingDatagramSendRequests.ToArray())
        {
            if (pendingDatagramSendRequests.TryRemove(entry.Key, out TaskCompletionSource<object?>? completion))
            {
                completion.TrySetException(completionException);
            }
        }
    }

    private void NotifyStreamObservers(ulong streamId, QuicStreamNotification notification)
    {
        if (!streamObservers.TryGetValue(streamId, out QuicStreamObserverSet? observers))
        {
            return;
        }

        observers.Notify(notification);
    }

    private void NotifyAllStreamObservers(Exception completionException)
    {
        if (streamObservers.IsEmpty)
        {
            return;
        }

        foreach (KeyValuePair<ulong, QuicStreamObserverSet> entry in streamObservers)
        {
            QuicStreamNotification notification = new(
                QuicStreamNotificationKind.ConnectionTerminated,
                completionException);

            entry.Value.Notify(notification);
        }
    }
}
