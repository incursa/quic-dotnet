using System.Collections.Concurrent;

namespace Incursa.Quic;

// Stream actions, flow-control publication, outbound payload construction, and observer plumbing.
internal sealed partial class QuicConnectionRuntime
{
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
        if (!streamRegistry.Bookkeeping.TryPeekLocalStream(bidirectional, out QuicStreamId streamId, out _))
        {
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

        ulong writeOffset = snapshot.UniqueBytesSent;
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

        if (!TryBuildOutboundStreamPayload(streamId, writeOffset, streamData.Span, finishWrites, out byte[] streamPayload))
        {
            completion.TrySetException(new InvalidOperationException("The connection runtime could not build the stream write payload."));
            return false;
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

        if (finishWrites)
        {
            TryReleasePeerStreamCapacity(streamId, ref effects);
        }

        AppendEffects(ref effects, RecomputeLifecycleTimerEffects());
        completion.TrySetResult(null);
        return true;
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

        if (!TryProtectAndAccountApplicationPayload(
            combinedPayload,
            "The connection runtime could not protect the queued stream write packet.",
            "The connection cannot send the queued stream write packet.",
            probePacket,
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
        ReadOnlySpan<byte> payload,
        string protectFailureMessage,
        string amplificationFailureMessage,
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
            out currentPath,
            out updatedAmplificationState,
            out protectedPacket,
            out exception);
    }

    private bool TryProtectAndAccountApplicationPayload(
        ReadOnlySpan<byte> payload,
        string protectFailureMessage,
        string amplificationFailureMessage,
        bool probePacket,
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

        if (!handshakeFlowCoordinator.TryBuildProtectedApplicationDataPacket(
            payload,
            tlsState.OneRttProtectPacketProtectionMaterial!.Value,
            tlsState.CurrentOneRttKeyPhase == 1,
            out ulong packetNumber,
            out protectedPacket))
        {
            exception = new InvalidOperationException(protectFailureMessage);
            return false;
        }

        if (!sendRuntime.FlowController.CanSend(
            QuicPacketNumberSpace.ApplicationData,
            (ulong)protectedPacket.Length,
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

        TrackApplicationPacket(packetNumber, protectedPacket, probePacket: probePacket);
        exception = null;
        return true;
    }

    private bool TryProtectAndAccountApplicationPayloadOnPath(
        QuicConnectionPathIdentity pathIdentity,
        ReadOnlySpan<byte> payload,
        string protectFailureMessage,
        string amplificationFailureMessage,
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
        if (!handshakeFlowCoordinator.TryBuildProtectedApplicationDataPacket(
            payload,
            tlsState.OneRttProtectPacketProtectionMaterial!.Value,
            tlsState.CurrentOneRttKeyPhase == 1,
            out ulong packetNumber,
            out protectedPacket))
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

        TrackApplicationPacket(packetNumber, protectedPacket);
        sendPathIdentity = pathIdentity;
        exception = null;
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
        bool retransmittable = true,
        bool probePacket = false,
        QuicTlsEncryptionLevel packetProtectionLevel = QuicTlsEncryptionLevel.OneRtt)
    {
        sendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber,
            (ulong)protectedPacket.Length,
            GetElapsedMicros(lastTransitionTicks),
            ProbePacket: probePacket,
            Retransmittable: retransmittable,
            PacketBytes: protectedPacket,
            PacketProtectionLevel: packetProtectionLevel));
        recoveryController.RecordPacketSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber,
            GetElapsedMicros(lastTransitionTicks),
            isAckElicitingPacket: true,
            isProbePacket: probePacket);
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
            isProbePacket: probePacket);
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
