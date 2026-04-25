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
                    ReadOnlyMemory<byte>.Empty,
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

        if (!TryProtectAndAccountApplicationPayload(
            streamPayload,
            "The connection runtime could not protect the stream open packet.",
            "The connection cannot send the stream open packet.",
            ref effects,
            out QuicConnectionActivePathRecord currentPath,
            out QuicConnectionPathAmplificationState updatedAmplificationState,
            out byte[] protectedPacket,
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

        activePath = currentPath with
        {
            AmplificationState = updatedAmplificationState,
        };

        AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(
            currentPath.Identity,
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

        if (!streamRegistry.Bookkeeping.TryGetStreamSnapshot(streamId, out QuicConnectionStreamSnapshot snapshot))
        {
            completion.TrySetException(new InvalidOperationException("The stream is not available on this connection."));
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
            && pendingApplicationSendRequests.Any(pendingWrite => pendingWrite.StreamId == streamId);
        if (queuedWritesPendingForStream)
        {
            if (!TryPromoteQueuedApplicationSendToFinal(streamId))
            {
                return FailWriteAfterRollback(
                    completion,
                    sendStateBeforeWrite,
                    new InvalidOperationException("The connection runtime could not mark the queued stream write as final."));
            }

            if (!FlushPendingApplicationSends(nowTicks, ref effects))
            {
                return FailWriteAfterRollback(
                    completion,
                    sendStateBeforeWrite,
                    new InvalidOperationException("The connection runtime could not flush queued stream writes before finishing the writable side."));
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

        if (ShouldDelayApplicationSend(streamData.Span))
        {
            QueuePendingApplicationSend(streamId, streamPayload, nowTicks, ref effects);
            completion.TrySetResult(null);
            return true;
        }

        if (!TryProtectAndAccountApplicationPayload(
            streamPayload,
            "The connection runtime could not protect the stream write packet.",
            "The connection cannot send the stream write packet.",
            new[] { streamId },
            ref effects,
            out QuicConnectionActivePathRecord currentPath,
            out QuicConnectionPathAmplificationState updatedAmplificationState,
            out byte[] protectedPacket,
            out exception))
        {
            return FailWriteAfterRollback(
                completion,
                sendStateBeforeWrite,
                exception!);
        }

        activePath = currentPath with
        {
            AmplificationState = updatedAmplificationState,
        };

        AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(
            currentPath.Identity,
            protectedPacket));

        if (finishWrites)
        {
            TryReleasePeerStreamCapacity(streamId, ref effects);
        }

        AppendEffects(ref effects, RecomputeLifecycleTimerEffects());
        completion.TrySetResult(null);
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
            && (pendingApplicationSendRequests.Count > 0
                || streamData.Length < ApplicationSendDelayThresholdBytes);
    }

    private void QueuePendingApplicationSend(
        ulong streamId,
        byte[] streamPayload,
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        pendingApplicationSendRequests.Add(new PendingApplicationSendRequest(streamId, streamPayload));

        if (pendingApplicationSendRequests.Count == 1)
        {
            pendingApplicationSendDelayDueTicks = SaturatingAdd(
                nowTicks,
                ConvertMicrosToTicks(ApplicationSendDelayMicros));
        }

        AppendEffects(ref effects, RecomputeLifecycleTimerEffects());
    }

    private bool TryPromoteQueuedApplicationSendToFinal(ulong streamId)
    {
        for (int index = pendingApplicationSendRequests.Count - 1; index >= 0; index--)
        {
            PendingApplicationSendRequest queuedWrite = pendingApplicationSendRequests[index];
            if (queuedWrite.StreamId != streamId)
            {
                continue;
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

            pendingApplicationSendRequests[index] = new PendingApplicationSendRequest(streamId, finalPayload);
            return true;
        }

        return false;
    }

    private bool FlushPendingApplicationSends(long nowTicks, ref List<QuicConnectionEffect>? effects)
        => FlushPendingApplicationSends(nowTicks, probePacket: false, ref effects);

    private bool FlushPendingApplicationSends(
        long nowTicks,
        bool probePacket,
        ref List<QuicConnectionEffect>? effects)
    {
        _ = nowTicks;

        if (pendingApplicationSendRequests.Count == 0)
        {
            pendingApplicationSendDelayDueTicks = null;
            return false;
        }

        PendingApplicationSendRequest[] queuedWrites = pendingApplicationSendRequests.ToArray();
        pendingApplicationSendRequests.Clear();
        pendingApplicationSendDelayDueTicks = null;

        int combinedPayloadLength = 0;
        foreach (PendingApplicationSendRequest queuedWrite in queuedWrites)
        {
            combinedPayloadLength = checked(combinedPayloadLength + queuedWrite.StreamPayload.Length);
        }

        byte[] combinedPayload = new byte[combinedPayloadLength];
        int copyOffset = 0;
        foreach (PendingApplicationSendRequest queuedWrite in queuedWrites)
        {
            queuedWrite.StreamPayload.CopyTo(combinedPayload.AsSpan(copyOffset));
            copyOffset += queuedWrite.StreamPayload.Length;
        }

        ulong[] streamIds = BuildDistinctStreamIds(queuedWrites);

        if (!TryProtectAndAccountApplicationPayload(
            combinedPayload,
            "The connection runtime could not protect the queued stream write packet.",
            "The connection cannot send the queued stream write packet.",
            probePacket,
            ackOnlyPacket: false,
            streamIds,
            ref effects,
            out QuicConnectionActivePathRecord currentPath,
            out QuicConnectionPathAmplificationState updatedAmplificationState,
            out byte[] protectedPacket,
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

    private void TryRemoveQueuedApplicationSendsForStream(ulong streamId, ref List<QuicConnectionEffect>? effects)
    {
        if (pendingApplicationSendRequests.Count == 0)
        {
            return;
        }

        bool removedAny = false;
        for (int index = pendingApplicationSendRequests.Count - 1; index >= 0; index--)
        {
            if (pendingApplicationSendRequests[index].StreamId != streamId)
            {
                continue;
            }

            pendingApplicationSendRequests.RemoveAt(index);
            removedAny = true;
        }

        if (removedAny && pendingApplicationSendRequests.Count == 0)
        {
            pendingApplicationSendDelayDueTicks = null;
            AppendEffects(ref effects, RecomputeLifecycleTimerEffects());
        }
    }

    private static ulong[] BuildDistinctStreamIds(ReadOnlySpan<PendingApplicationSendRequest> queuedWrites)
    {
        if (queuedWrites.IsEmpty)
        {
            return [];
        }

        ulong[] streamIds = new ulong[queuedWrites.Length];
        int uniqueCount = 0;

        foreach (PendingApplicationSendRequest queuedWrite in queuedWrites)
        {
            bool alreadyPresent = false;
            for (int index = 0; index < uniqueCount; index++)
            {
                if (streamIds[index] == queuedWrite.StreamId)
                {
                    alreadyPresent = true;
                    break;
                }
            }

            if (!alreadyPresent)
            {
                streamIds[uniqueCount++] = queuedWrite.StreamId;
            }
        }

        if (uniqueCount != streamIds.Length)
        {
            Array.Resize(ref streamIds, uniqueCount);
        }

        return streamIds;
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
            return TrySendFlowControlBlockedSignal(
                dataBlockedFrame,
                "The connection runtime could not protect the data-blocked packet.",
                "The connection cannot send the data-blocked packet.",
                ref effects);
        }

        if (streamDataBlockedFrame.MaximumStreamData != 0)
        {
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
            out byte[] protectedPacket,
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
            out byte[] protectedPacket,
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
            out byte[] protectedPacket,
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
            out byte[] protectedPacket,
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
            out byte[] protectedPacket,
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
            out byte[] protectedPacket,
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
            out byte[] protectedPacket,
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
            out byte[] protectedPacket,
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
            out byte[] protectedPacket,
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
        out byte[] protectedPacket,
        out Exception? exception)
    {
        return TryProtectAndAccountApplicationPayload(
            payload,
            protectFailureMessage,
            amplificationFailureMessage,
            probePacket: false,
            ackOnlyPacket: false,
            streamIds: null,
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
        ulong[]? streamIds,
        ref List<QuicConnectionEffect>? effects,
        out QuicConnectionActivePathRecord currentPath,
        out QuicConnectionPathAmplificationState updatedAmplificationState,
        out byte[] protectedPacket,
        out Exception? exception)
    {
        return TryProtectAndAccountApplicationPayload(
            payload,
            protectFailureMessage,
            amplificationFailureMessage,
            probePacket: false,
            ackOnlyPacket: false,
            streamIds,
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
        ref List<QuicConnectionEffect>? effects,
        out QuicConnectionActivePathRecord currentPath,
        out QuicConnectionPathAmplificationState updatedAmplificationState,
        out byte[] protectedPacket,
        out Exception? exception)
    {
        currentPath = default;
        updatedAmplificationState = default;
        protectedPacket = [];

        currentPath = activePath!.Value;
        if (!currentPath.MaximumDatagramSizeState.CanSendOrdinaryPackets)
        {
            exception = new InvalidOperationException("The active path cannot send ordinary packets.");
            return false;
        }

        if (!TryPrepareOneRttProtectionForAeadLimit(protectFailureMessage, ref effects, out exception))
        {
            return false;
        }

        ulong nowMicros = GetElapsedMicros(lastTransitionTicks);
        ReadOnlyMemory<byte> packetPayload = payload;
        QuicAckFrame? piggybackedAckFrame = null;
        if (!ackOnlyPacket
            && TryBuildApplicationAckPiggybackPayload(
                payload,
                nowMicros,
                out byte[] piggybackedPayload,
                out QuicAckFrame includedAckFrame))
        {
            packetPayload = piggybackedPayload;
            piggybackedAckFrame = includedAckFrame;
        }

        if (!handshakeFlowCoordinator.TryBuildProtectedApplicationDataPacket(
            packetPayload.Span,
            tlsState.OneRttProtectPacketProtectionMaterial!.Value,
            tlsState.CurrentOneRttKeyPhaseBit,
            out ulong packetNumber,
            out protectedPacket))
        {
            exception = new InvalidOperationException(protectFailureMessage);
            return false;
        }

        if (!tlsState.TryRecordCurrentOneRttProtectionUse())
        {
            exception = new InvalidOperationException(protectFailureMessage);
            return false;
        }

        if (!sendRuntime.FlowController.CanSend(
            QuicPacketNumberSpace.ApplicationData,
            (ulong)protectedPacket.Length,
            isAckOnlyPacket: ackOnlyPacket,
            isProbePacket: probePacket))
        {
            exception = new InvalidOperationException("The congestion controller cannot send another ordinary packet.");
            return false;
        }

        if (!currentPath.MaximumDatagramSizeState.CanSend((ulong)protectedPacket.Length))
        {
            exception = new InvalidOperationException("The active path cannot send an ordinary packet.");
            return false;
        }

        if (!currentPath.AmplificationState.TryConsumeSendBudget(
            protectedPacket.Length,
            out updatedAmplificationState))
        {
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
            plaintextPayload: payload);
        if (piggybackedAckFrame is not null)
        {
            sendRuntime.FlowController.MarkAckFrameSent(
                QuicPacketNumberSpace.ApplicationData,
                packetNumber,
                piggybackedAckFrame,
                nowMicros,
                ackOnlyPacket: false);
        }

        exception = null;
        return true;
    }

    private bool TryBuildApplicationAckPiggybackPayload(
        ReadOnlyMemory<byte> payload,
        ulong nowMicros,
        out byte[] piggybackedPayload,
        out QuicAckFrame ackFrame)
    {
        piggybackedPayload = [];
        ackFrame = new QuicAckFrame();

        if (payload.IsEmpty
            || !sendRuntime.FlowController.ShouldIncludeAckFrameWithOutgoingPacket(
                QuicPacketNumberSpace.ApplicationData,
                nowMicros,
                maxAckDelayMicros: 0)
            || !sendRuntime.FlowController.TryBuildAckFrame(
                QuicPacketNumberSpace.ApplicationData,
                nowMicros,
                out ackFrame)
            || !TryBuildOutboundAckFramePayload(ackFrame, out byte[] ackPayload))
        {
            return false;
        }

        piggybackedPayload = new byte[checked(ackPayload.Length + payload.Length)];
        ackPayload.CopyTo(piggybackedPayload.AsSpan());
        payload.Span.CopyTo(piggybackedPayload.AsSpan(ackPayload.Length));
        return true;
    }

    private bool TryProtectAndAccountApplicationPayloadOnPath(
        QuicConnectionPathIdentity pathIdentity,
        ReadOnlyMemory<byte> payload,
        string protectFailureMessage,
        string amplificationFailureMessage,
        ref List<QuicConnectionEffect>? effects,
        out QuicConnectionPathIdentity sendPathIdentity,
        out byte[] protectedPacket,
        out Exception? exception)
    {
        sendPathIdentity = default;
        protectedPacket = [];

        if (!tlsState.OneRttProtectPacketProtectionMaterial.HasValue)
        {
            exception = new InvalidOperationException(protectFailureMessage);
            return false;
        }
        if (!TryPrepareOneRttProtectionForAeadLimit(protectFailureMessage, ref effects, out exception))
        {
            return false;
        }

        if (!handshakeFlowCoordinator.TryBuildProtectedApplicationDataPacket(
            payload.Span,
            tlsState.OneRttProtectPacketProtectionMaterial!.Value,
            tlsState.CurrentOneRttKeyPhaseBit,
            out ulong packetNumber,
            out protectedPacket))
        {
            exception = new InvalidOperationException(protectFailureMessage);
            return false;
        }

        if (!tlsState.TryRecordCurrentOneRttProtectionUse())
        {
            exception = new InvalidOperationException(protectFailureMessage);
            return false;
        }

        if (!sendRuntime.FlowController.CanSend(
            QuicPacketNumberSpace.ApplicationData,
            (ulong)protectedPacket.Length))
        {
            exception = new InvalidOperationException("The congestion controller cannot send another ordinary packet.");
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
            exception = new InvalidOperationException(amplificationFailureMessage);
            return false;
        }

        TrackApplicationPacket(packetNumber, protectedPacket, plaintextPayload: payload);
        sendPathIdentity = pathIdentity;
        exception = null;
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

    private bool TryFlushPendingRetransmissions(
        QuicPacketNumberSpace packetNumberSpace,
        long nowTicks,
        bool probePacket,
        ref List<QuicConnectionEffect>? effects)
    {
        if (activePath is null || sendRuntime.PendingRetransmissionCount == 0)
        {
            return false;
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
            if ((rebuildableCryptoRetransmission
                    && !TryBuildCryptoRetransmissionPacket(
                        probeRetransmission,
                        out _,
                        out rebuiltPacketNumber,
                        out rebuiltDatagram))
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
                return false;
            }

            QuicConnectionActivePathRecord currentPath = activePath.Value;
            if (!currentPath.MaximumDatagramSizeState.CanSendOrdinaryPackets
                || !currentPath.MaximumDatagramSizeState.CanSend((ulong)datagram.Length)
                || !sendRuntime.FlowController.CanSend(
                    probeRetransmission.PacketNumberSpace,
                    (ulong)datagram.Length,
                    isAckOnlyPacket: false,
                    isProbePacket: probePacket)
                || !currentPath.AmplificationState.TryConsumeSendBudget(
                    datagram.Length,
                    out QuicConnectionPathAmplificationState updatedAmplificationState))
            {
                sendRuntime.QueueRetransmission(probeRetransmission);
                return false;
            }

            activePath = currentPath with
            {
                AmplificationState = updatedAmplificationState,
            };

            if (rebuildableCryptoRetransmission)
            {
                TrackCryptoRetransmissionSent(
                    currentPath.Identity,
                    cryptoProtectionLevel,
                    rebuiltPacketNumber,
                    datagram.ToArray(),
                    probePacket,
                    ref effects);
            }
            else if (rebuildableApplicationRetransmission)
            {
                TrackApplicationRetransmissionSent(
                    rebuiltPacketNumber,
                    datagram.ToArray(),
                    sentAtMicros,
                    probePacket,
                    probeRetransmission.StreamIds,
                    rebuiltApplicationPayload);
            }
            else
            {
                TrackRetransmissionPlanSent(
                    currentPath.Identity,
                    probeRetransmission,
                    sentAtMicros,
                    probePacket,
                    ref effects);
            }

            AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(
                currentPath.Identity,
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
            if ((rebuildableCryptoRetransmission
                    && !TryBuildCryptoRetransmissionPacket(
                        retransmission,
                        out _,
                        out rebuiltPacketNumber,
                        out rebuiltDatagram))
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
                continue;
            }

            QuicConnectionActivePathRecord currentPath = activePath.Value;
            if (!currentPath.MaximumDatagramSizeState.CanSendOrdinaryPackets
                || !currentPath.MaximumDatagramSizeState.CanSend((ulong)datagram.Length)
                || !sendRuntime.FlowController.CanSend(
                    retransmission.PacketNumberSpace,
                    (ulong)datagram.Length,
                    isAckOnlyPacket: false,
                    isProbePacket: probePacket)
                || !currentPath.AmplificationState.TryConsumeSendBudget(
                    datagram.Length,
                    out QuicConnectionPathAmplificationState updatedAmplificationState))
            {
                sendRuntime.QueueRetransmission(retransmission);
                break;
            }

            activePath = currentPath with
            {
                AmplificationState = updatedAmplificationState,
            };

            if (rebuildableCryptoRetransmission)
            {
                TrackCryptoRetransmissionSent(
                    currentPath.Identity,
                    cryptoProtectionLevel,
                    rebuiltPacketNumber,
                    datagram.ToArray(),
                    probePacket,
                    ref effects);
            }
            else if (rebuildableApplicationRetransmission)
            {
                TrackApplicationRetransmissionSent(
                    rebuiltPacketNumber,
                    datagram.ToArray(),
                    sentAtMicros,
                    probePacket,
                    retransmission.StreamIds,
                    rebuiltApplicationPayload);
            }
            else
            {
                TrackRetransmissionPlanSent(
                    currentPath.Identity,
                    retransmission,
                    sentAtMicros,
                    probePacket,
                    ref effects);
            }

            AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(
                currentPath.Identity,
                datagram));
            sentAny = true;

            if (probePacket)
            {
                break;
            }
        }

        return sentAny;
    }

    private bool TryDequeuePreferredProbeRetransmission(
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
        ref List<QuicConnectionEffect>? effects)
    {
        if (activePath is null
            || !IsInitialAndHandshakePair(firstPacketNumberSpace, secondPacketNumberSpace))
        {
            return false;
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
            if (!TryBuildCryptoRetransmissionPacket(
                    initialRetransmission,
                    initialDestinationConnectionIdOverride,
                    out _,
                    out ulong rebuiltInitialPacketNumber,
                    out byte[] rebuiltInitialPacketBytes)
                || !TryBuildCryptoRetransmissionPacket(
                    handshakeRetransmission,
                    out _,
                    out ulong rebuiltHandshakePacketNumber,
                    out byte[] rebuiltHandshakePacketBytes))
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
            TrackCryptoRetransmissionSent(
                currentPath.Identity,
                QuicTlsEncryptionLevel.Handshake,
                rebuiltHandshakePacketNumber,
                rebuiltHandshakePacketBytes,
                probePacket: true,
                ref effects);

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

            if (queueHandshakeForRetry)
            {
                sendRuntime.QueueRetransmission(handshakeRetransmission);
            }
        }
    }

    private bool TrySendCoalescedHandshakeAndApplicationRecoveryProbeDatagram(
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        if (activePath is null)
        {
            return false;
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
            ReadOnlySpan<byte> handshakeDestinationConnectionIdOverride =
                CurrentPeerDestinationConnectionId.IsEmpty
                    ? ReadOnlySpan<byte>.Empty
                    : CurrentPeerDestinationConnectionId.Span;

            if (!TryGetCryptoRetransmissionProtectionLevel(
                    handshakeRetransmission,
                    out QuicTlsEncryptionLevel handshakeProtectionLevel)
                || handshakeProtectionLevel != QuicTlsEncryptionLevel.Handshake
                || !TryBuildHandshakeCryptoRetransmissionPacketWithDestinationOverride(
                    handshakeRetransmission,
                    handshakeDestinationConnectionIdOverride,
                    out ulong rebuiltHandshakePacketNumber,
                    out byte[] rebuiltHandshakePacketBytes)
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
            ulong sentAtMicros = GetElapsedMicros(nowTicks);
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

            if (queueApplicationForRetry)
            {
                sendRuntime.QueueRetransmission(applicationRetransmission);
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
        out QuicTlsEncryptionLevel packetProtectionLevel,
        out ulong packetNumber,
        out byte[] protectedPacket)
    {
        return TryBuildCryptoRetransmissionPacket(
            retransmission,
            ReadOnlySpan<byte>.Empty,
            out packetProtectionLevel,
            out packetNumber,
            out protectedPacket);
    }

    private bool TryBuildCryptoRetransmissionPacket(
        QuicConnectionRetransmissionPlan retransmission,
        ReadOnlySpan<byte> initialDestinationConnectionIdOverride,
        out QuicTlsEncryptionLevel packetProtectionLevel,
        out ulong packetNumber,
        out byte[] protectedPacket)
    {
        packetNumber = default;
        protectedPacket = [];

        if (!TryGetCryptoRetransmissionProtectionLevel(retransmission, out packetProtectionLevel))
        {
            return false;
        }

        return packetProtectionLevel switch
        {
            QuicTlsEncryptionLevel.Initial => TryBuildInitialCryptoRetransmissionPacket(
                retransmission,
                initialDestinationConnectionIdOverride,
                out packetNumber,
                out protectedPacket),
            QuicTlsEncryptionLevel.Handshake => TryBuildHandshakeCryptoRetransmissionPacket(
                retransmission,
                out packetNumber,
                out protectedPacket),
            _ => false,
        };
    }

    private bool TryBuildInitialCryptoRetransmissionPacket(
        QuicConnectionRetransmissionPlan retransmission,
        ReadOnlySpan<byte> destinationConnectionIdOverride,
        out ulong packetNumber,
        out byte[] protectedPacket)
    {
        packetNumber = default;
        protectedPacket = [];

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

        return handshakeFlowCoordinator.TryBuildProtectedInitialPacketForRetransmission(
            cryptoPayload,
            cryptoOffset,
            longHeader.DestinationConnectionId,
            destinationConnectionId,
            longHeader.SourceConnectionId,
            parsedRetryToken,
            initialPacketProtection,
            out packetNumber,
            out protectedPacket);
    }

    private bool TryBuildHandshakeCryptoRetransmissionPacket(
        QuicConnectionRetransmissionPlan retransmission,
        out ulong packetNumber,
        out byte[] protectedPacket)
    {
        packetNumber = default;
        protectedPacket = [];

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

        return handshakeFlowCoordinator.TryBuildProtectedHandshakePacketForRetransmission(
            cryptoPayload,
            cryptoOffset,
            longHeader.DestinationConnectionId,
            longHeader.SourceConnectionId,
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
        out ulong packetNumber,
        out byte[] protectedPacket)
    {
        packetNumber = default;
        protectedPacket = [];

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

        return handshakeFlowCoordinator.TryBuildProtectedHandshakePacketForRetransmission(
            cryptoPayload,
            cryptoOffset,
            destinationConnectionId,
            longHeader.SourceConnectionId,
            handshakeMaterial,
            out packetNumber,
            out protectedPacket);
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

    private void TrackApplicationPacket(
        ulong packetNumber,
        byte[] protectedPacket,
        bool ackEliciting = true,
        bool ackOnlyPacket = false,
        bool retransmittable = true,
        bool probePacket = false,
        QuicTlsEncryptionLevel packetProtectionLevel = QuicTlsEncryptionLevel.OneRtt,
        ulong[]? streamIds = null,
        ReadOnlyMemory<byte> plaintextPayload = default)
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

        int bufferLength = Math.Max(ApplicationMinimumProtectedPayloadLength, streamData.Length + 32);
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

    internal bool TryBuildOutboundNewTokenPayload(ReadOnlySpan<byte> token, out byte[] payload)
    {
        payload = [];

        if (token.IsEmpty)
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

    private bool TryHandleResetStreamFrame(QuicResetStreamFrame resetStreamFrame, ref List<QuicConnectionEffect>? effects)
    {
        if (!streamRegistry.Bookkeeping.TryReceiveResetStreamFrame(
            resetStreamFrame,
            out QuicMaxDataFrame maxDataFrame,
            out QuicTransportErrorCode errorCode,
            suppressResetSignalWhenDataRecvd: true))
        {
            _ = errorCode;
            return false;
        }

        if (maxDataFrame.MaximumData != 0)
        {
            _ = TryEmitFlowControlCreditUpdate(maxDataFrame, default, ref effects);
        }

        if (streamRegistry.Bookkeeping.TryGetStreamSnapshot(resetStreamFrame.StreamId, out QuicConnectionStreamSnapshot snapshot)
            && snapshot.ReceiveState == QuicStreamReceiveState.ResetRecvd)
        {
            NotifyStreamObservers(
                resetStreamFrame.StreamId,
                new QuicStreamNotification(
                    QuicStreamNotificationKind.ReadAborted,
                    CreateStreamReadAbortedException(resetStreamFrame.ApplicationProtocolErrorCode)));

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
            out byte[] protectedPacket,
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
        _ = inboundStreamIds.Writer.TryWrite(streamId);
    }

    private void CompletePendingStreamOperations(Exception completionException)
    {
        CompleteInboundStreamQueue(completionException);
        CompletePendingStreamOpenRequests(completionException);
        CompletePendingStreamActionRequests(completionException);
        pendingApplicationSendRequests.Clear();
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

    private void NotifyStreamObservers(ulong streamId, QuicStreamNotification notification)
    {
        if (!streamObservers.TryGetValue(streamId, out ConcurrentDictionary<long, Action<QuicStreamNotification>>? observers))
        {
            return;
        }

        foreach (Action<QuicStreamNotification> observer in observers.Values)
        {
            try
            {
                observer(notification);
            }
            catch
            {
                // Stream observer failures remain local to the public facade boundary.
            }
        }
    }

    private void NotifyAllStreamObservers(Exception completionException)
    {
        if (streamObservers.IsEmpty)
        {
            return;
        }

        foreach (KeyValuePair<ulong, ConcurrentDictionary<long, Action<QuicStreamNotification>>> entry in streamObservers)
        {
            QuicStreamNotification notification = new(
                QuicStreamNotificationKind.ConnectionTerminated,
                completionException);

            foreach (Action<QuicStreamNotification> observer in entry.Value.Values)
            {
                try
                {
                    observer(notification);
                }
                catch
                {
                    // Stream observer failures remain local to the public facade boundary.
                }
            }
        }
    }
}
