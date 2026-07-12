// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers;
using System.Collections.Concurrent;
using System.Runtime.CompilerServices;

namespace Incursa.Quic;

// Stream actions, flow-control publication, outbound payload construction, and observer plumbing.
internal sealed partial class QuicConnectionRuntime
{
    private static readonly bool ApplicationSendDebugEnabled =
        string.Equals(
            Environment.GetEnvironmentVariable("INCURSA_QUIC_DEBUG_APP_RX"),
            "1",
            StringComparison.Ordinal);

    private static void LogApplicationSend(ref ApplicationSendLogInterpolatedStringHandler message)
    {
        if (message.Enabled)
        {
            Console.Error.WriteLine(message.GetFormattedText());
        }
    }

#pragma warning disable S1144 // The C# compiler calls these members for LogApplicationSend interpolated strings.
    [InterpolatedStringHandler]
    private ref struct ApplicationSendLogInterpolatedStringHandler
    {
        private DefaultInterpolatedStringHandler builder;

        public ApplicationSendLogInterpolatedStringHandler(int literalLength, int formattedCount, out bool shouldAppend)
        {
            Enabled = ApplicationSendDebugEnabled;
            shouldAppend = Enabled;
            builder = Enabled
                ? new DefaultInterpolatedStringHandler(literalLength, formattedCount)
                : default;
        }

        public bool Enabled { get; }

        public void AppendLiteral(string value)
        {
            if (Enabled)
            {
                builder.AppendLiteral(value);
            }
        }

        public void AppendFormatted<T>(T value)
        {
            if (Enabled)
            {
                builder.AppendFormatted(value);
            }
        }

        public void AppendFormatted<T>(T value, string? format)
        {
            if (Enabled)
            {
                builder.AppendFormatted(value, format);
            }
        }

        public void AppendFormatted<T>(T value, int alignment)
        {
            if (Enabled)
            {
                builder.AppendFormatted(value, alignment);
            }
        }

        public void AppendFormatted<T>(T value, int alignment, string? format)
        {
            if (Enabled)
            {
                builder.AppendFormatted(value, alignment, format);
            }
        }

        public string GetFormattedText()
            => Enabled ? builder.ToStringAndClear() : string.Empty;
    }
#pragma warning restore S1144

    private const string StreamWriteSendBlockedMessage = "The connection cannot send the stream write packet.";
    private const string QueuedStreamWriteSendBlockedMessage = "The connection cannot send the queued stream write packet.";
    private const string DatagramSendBlockedMessage = "The connection cannot send the DATAGRAM packet.";

    private bool HandleStreamAction(
        QuicConnectionStreamActionEvent streamActionEvent,
        long nowTicks,
        ref QuicConnectionEffectAccumulator effects)
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
            QuicConnectionStreamActionKind.ReleaseCapacity
                => HandleReleaseCapacityStreamAction(ref effects),
            _ => false,
        };
    }

    private bool HandleDatagramSendRequested(
        QuicConnectionDatagramSendRequestedEvent datagramSendRequestedEvent,
        ref QuicConnectionEffectAccumulator effects)
    {
        if (!pendingDatagramSendRequests.TryRemove(
                datagramSendRequestedEvent.RequestId,
                out QuicConnectionRuntime.DatagramSendRequestCompletionSource? completion))
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

        QuicConnectionPathIdentity selectedPathIdentity = activePath!.Value.Identity;
        if (TryGetPermittedPeerMigrationSendPath(out QuicConnectionPathIdentity peerMigrationPathIdentity))
        {
            selectedPathIdentity = peerMigrationPathIdentity;
        }

        if (!TryProtectAndAccountApplicationPayloadOnPath(
                selectedPathIdentity,
                datagramPayload,
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
                completion.TrySetResult();
                return false;
            }

            completion.TrySetException(exception!);
            return false;
        }

        AppendSendDatagramEffect(ref effects,
            sendPathIdentity,
            protectedPacket);
        AppendLifecycleTimerEffects(ref effects);
        completion.TrySetResult();
        return true;
    }

    private bool HandleOpenStreamAction(
        long requestId,
        QuicStreamType streamType,
        ref QuicConnectionEffectAccumulator effects)
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
        ref QuicConnectionEffectAccumulator effects)
    {
        if (pendingStreamOpenRequests.IsEmpty)
        {
            return false;
        }

        bool stateChanged = false;
        KeyValuePair<long, StreamOpenRequestCompletionSource>[] pendingRequests = pendingStreamOpenRequests.ToArray();
        Array.Sort(pendingRequests, static (left, right) => left.Key.CompareTo(right.Key));

        foreach (KeyValuePair<long, StreamOpenRequestCompletionSource> pendingRequest in pendingRequests)
        {
            QuicStreamType streamType = pendingRequest.Value.StreamType;
            if ((streamType == QuicStreamType.Bidirectional) != bidirectional)
            {
                continue;
            }

            if (!TryProcessPendingStreamOpenRequest(
                pendingRequest.Key,
                streamType,
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

    private bool TryRetryPendingStreamWriteRequests(
        long nowTicks,
        ref QuicConnectionEffectAccumulator effects)
    {
        KeyValuePair<long, QuicConnectionRuntime.StreamActionRequestCompletionSource>[]? pendingRequests = null;
        int pendingRequestCount = 0;
        lock (pendingStreamActionRequestsGate)
        {
            if (pendingStreamActionRequests.Count == 0)
            {
                return false;
            }

            pendingRequestCount = pendingStreamActionRequests.Count;
            pendingRequests = ArrayPool<KeyValuePair<long, QuicConnectionRuntime.StreamActionRequestCompletionSource>>.Shared.Rent(pendingRequestCount);
            int snapshotIndex = 0;
            foreach (KeyValuePair<long, QuicConnectionRuntime.StreamActionRequestCompletionSource> pendingRequest in pendingStreamActionRequests)
            {
                pendingRequests[snapshotIndex++] = pendingRequest;
            }

            SortPendingStreamActionRequests(pendingRequests, pendingRequestCount);

            bool stateChanged = false;
            try
            {
                for (int index = 0; index < pendingRequestCount; index++)
                {
                    KeyValuePair<long, QuicConnectionRuntime.StreamActionRequestCompletionSource> pendingRequest = pendingRequests[index];
                    QuicConnectionRuntime.StreamActionRequestCompletionSource completion = pendingRequest.Value;
                    if (completion.ActionKind is not (QuicConnectionStreamActionKind.Write or QuicConnectionStreamActionKind.Finish))
                    {
                        continue;
                    }

                    if (completion.ActionKind == QuicConnectionStreamActionKind.Write
                        && !completion.HasOwnedStreamData)
                    {
                        continue;
                    }

                    if (completion.ActionKind == QuicConnectionStreamActionKind.Finish
                        && completion.StreamDataLength > 0
                        && !completion.HasOwnedStreamData)
                    {
                        continue;
                    }

                    if (!pendingStreamActionRequests.TryGetValue(pendingRequest.Key, out QuicConnectionRuntime.StreamActionRequestCompletionSource? currentCompletion)
                        || !ReferenceEquals(currentCompletion, completion))
                    {
                        continue;
                    }

                    if (HandleWriteStreamAction(
                            nowTicks,
                            pendingRequest.Key,
                            completion.StreamId,
                            completion.GetOwnedStreamDataMemory(),
                            completion.ActionKind == QuicConnectionStreamActionKind.Finish,
                            ref effects))
                    {
                        stateChanged = true;
                    }
                }

                return stateChanged;
            }
            finally
            {
                if (pendingRequests is not null)
                {
                    ArrayPool<KeyValuePair<long, QuicConnectionRuntime.StreamActionRequestCompletionSource>>.Shared.Return(
                        pendingRequests,
                        clearArray: true);
                }
            }
        }
    }

    private static void SortPendingStreamActionRequests(
        KeyValuePair<long, StreamActionRequestCompletionSource>[] pendingRequests,
        int pendingRequestCount)
    {
        for (int index = 1; index < pendingRequestCount; index++)
        {
            KeyValuePair<long, StreamActionRequestCompletionSource> item = pendingRequests[index];
            int insertIndex = index - 1;
            while (insertIndex >= 0 && pendingRequests[insertIndex].Key > item.Key)
            {
                pendingRequests[insertIndex + 1] = pendingRequests[insertIndex];
                insertIndex--;
            }

            pendingRequests[insertIndex + 1] = item;
        }
    }

    private bool TryProcessPendingStreamOpenRequest(
        long requestId,
        QuicStreamType streamType,
        ref QuicConnectionEffectAccumulator effects,
        out bool stillPending)
    {
        stillPending = false;

        if (!pendingStreamOpenRequests.TryGetValue(requestId, out QuicConnectionRuntime.StreamOpenRequestCompletionSource? completion)
            || completion.StreamType != streamType)
        {
            return false;
        }

        if (!TryValidateStreamSendBoundary(out Exception? exception))
        {
            if (TryRemovePendingStreamOpenRequest(requestId, out QuicConnectionRuntime.StreamOpenRequestCompletionSource? removedCompletion))
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

        if (!TryRemovePendingStreamOpenRequest(requestId, out QuicConnectionRuntime.StreamOpenRequestCompletionSource? openCompletion))
        {
            return false;
        }

        if (!TryBuildOutboundStreamPayload(
                streamId.Value,
                0,
                ReadOnlySpan<byte>.Empty,
                fin: false,
                out byte[] streamPayload,
                out int streamPayloadLength))
        {
            openCompletion!.TrySetException(new InvalidOperationException("The connection runtime could not build the stream open payload."));
            return true;
        }

        if (!TryProtectAndAccountStreamApplicationPayload(
            streamPayload.AsMemory(0, streamPayloadLength),
            streamPayload,
            "The connection runtime could not protect the stream open packet.",
            "The connection cannot send the stream open packet.",
            probePacket: false,
            streamId: streamId.Value,
            streamIds: null,
            ref effects,
            out QuicConnectionPathIdentity sendPathIdentity,
            out ReadOnlyMemory<byte> protectedPacket,
            out Exception? payloadException))
        {
            QuicBufferPool.ReturnBytes(streamPayload);
            if (IsTransientCongestionExhaustion(payloadException))
            {
                if (!streamRegistry.Bookkeeping.TryOpenLocalStream(bidirectional, out QuicStreamId congestionCommittedStreamId, out QuicStreamsBlockedFrame congestionCommittedBlockedFrame))
                {
                    _ = congestionCommittedBlockedFrame;
                    openCompletion!.TrySetException(new InvalidOperationException("The connection runtime could not commit the stream open."));
                    return true;
                }

                if (congestionCommittedStreamId.Value != streamId.Value)
                {
                    openCompletion!.TrySetException(new InvalidOperationException("The connection runtime committed an unexpected outbound stream identifier."));
                    return true;
                }

                openCompletion!.TrySetResult(congestionCommittedStreamId.Value);
                return true;
            }

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

        AppendSendDatagramEffect(ref effects,
            sendPathIdentity,
            protectedPacket);
        AppendLifecycleTimerEffects(ref effects);

        openCompletion!.TrySetResult(committedStreamId.Value);
        return true;
    }

    private bool HandleWriteStreamAction(
        long nowTicks,
        long requestId,
        ulong streamId,
        ReadOnlyMemory<byte> streamData,
        bool finishWrites,
        ref QuicConnectionEffectAccumulator effects)
    {
        lock (pendingStreamActionRequestsGate)
        {
            if (!pendingStreamActionRequests.TryGetValue(requestId, out QuicConnectionRuntime.StreamActionRequestCompletionSource? completion))
            {
                return false;
            }

            if (!TryValidateStreamSendBoundary(out Exception? exception))
            {
                pendingStreamActionRequests.Remove(requestId);
                completion.TrySetException(exception!);
                return false;
            }

            if (!TryResolveOrOpenLocalWritableStreamSnapshot(
                    streamId,
                    out QuicConnectionStreamSnapshot snapshot,
                    out QuicTransportErrorCode openErrorCode))
            {
                pendingStreamActionRequests.Remove(requestId);
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
                pendingStreamActionRequests.Remove(requestId);
                completion.TrySetException(new InvalidOperationException("This stream does not have a writable side."));
                return false;
            }

            if (snapshot.SendState is QuicStreamSendState.DataSent
                or QuicStreamSendState.DataRecvd
                or QuicStreamSendState.ResetSent
                or QuicStreamSendState.ResetRecvd)
            {
                pendingStreamActionRequests.Remove(requestId);
                if (finishWrites)
                {
                    completion.TrySetResult();
                    return false;
                }

                completion.TrySetException(new InvalidOperationException("The writable side is already completed."));
                return false;
            }

            if (!streamRegistry.Bookkeeping.TryCaptureSendState(streamId, out QuicConnectionStreamSendStateSnapshot sendStateBeforeWrite))
            {
                pendingStreamActionRequests.Remove(requestId);
                completion.TrySetException(new InvalidOperationException("The stream send state is unavailable."));
                return false;
            }

            ulong writeOffset = snapshot.UniqueBytesSent;
            if (ApplicationSendDebugEnabled)
            {
                Console.Error.WriteLine(
                    $"app-tx role={tlsState.Role} stream={streamId} offset={writeOffset} length={streamData.Length} fin={finishWrites} " +
                    $"queue={applicationSendQueue.Count} retrans={sendRuntime.PendingRetransmissionCount} " +
                    $"ackInFlight={sendRuntime.HasAckElicitingPacketsInFlight} validated={(activePath?.AmplificationState.IsAddressValidated ?? false)} " +
                    $"oneRtt={tlsState.OneRttProtectPacketProtectionMaterial.HasValue} handshakeConfirmed={HandshakeConfirmed}.");
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
                    pendingStreamActionRequests.Remove(requestId);
                    completion.TrySetException(new QuicException(
                        QuicError.TransportError,
                        null,
                        (long)errorCode,
                        "The stream write could not be committed."));
                }
                else if (dataBlockedFrame.MaximumData != 0 || streamDataBlockedFrame.MaximumStreamData != 0)
                {
                    completion.EnsureOwnedStreamData(streamData.Span);
                    _ = TryEmitFlowControlBlockedSignal(dataBlockedFrame, streamDataBlockedFrame, ref effects);
                }
                else
                {
                    pendingStreamActionRequests.Remove(requestId);
                    completion.TrySetException(new InvalidOperationException("The stream write could not be committed."));
                }

                return dataBlockedFrame.MaximumData != 0 || streamDataBlockedFrame.MaximumStreamData != 0;
            }

            return HandleWriteStreamActionAfterReservation(
                nowTicks,
                requestId,
                completion,
                streamId,
                streamData,
                finishWrites,
                writeOffset,
                sendStateBeforeWrite,
                ref effects);
        }
    }

    private bool HandleWriteStreamActionAfterReservation(
        long nowTicks,
        long requestId,
        QuicConnectionRuntime.StreamActionRequestCompletionSource completion,
        ulong streamId,
        ReadOnlyMemory<byte> streamData,
        bool finishWrites,
        ulong writeOffset,
        QuicConnectionStreamSendStateSnapshot sendStateBeforeWrite,
        ref QuicConnectionEffectAccumulator effects)
    {
        ReadOnlySpan<byte> committedStreamData = completion.HasOwnedStreamData
            ? completion.GetOwnedStreamDataSpan()
            : streamData.Span;
        int committedStreamDataLength = committedStreamData.Length;

        LogApplicationSend(
            $"app-tx reserved role={tlsState.Role} stream={streamId} offset={writeOffset} length={committedStreamDataLength} fin={finishWrites} queue={applicationSendQueue.Count}.");

        bool queuedWritesPendingForStream = finishWrites
            && committedStreamDataLength == 0
            && applicationSendQueue.HasPendingWritesForStream(streamId);
        if (queuedWritesPendingForStream)
        {
            LogApplicationSend(
                $"app-tx branch=finish-queued-final role={tlsState.Role} stream={streamId} queue={applicationSendQueue.Count}.");
            if (!TryPromoteQueuedApplicationSendToFinal(streamId))
            {
                pendingStreamActionRequests.Remove(requestId);
                return FailWriteAfterRollback(
                    completion,
                    sendStateBeforeWrite,
                    new InvalidOperationException("The connection runtime could not mark the queued stream write as final."));
            }

            if (!FlushPendingApplicationSends(nowTicks, ref effects, out Exception? flushException))
            {
                if (IsTransientApplicationSendPathBlocked(flushException))
                {
                    pendingStreamActionRequests.Remove(requestId);
                    completion.TrySetResult();
                    return true;
                }

                pendingStreamActionRequests.Remove(requestId);
                return FailWriteAfterRollback(
                    completion,
                    sendStateBeforeWrite,
                    flushException ?? new InvalidOperationException("The connection runtime could not flush queued stream writes before finishing the writable side."));
            }

            TryReleasePeerStreamCapacity(streamId, ref effects);
            AppendLifecycleTimerEffects(ref effects);
            pendingStreamActionRequests.Remove(requestId);
            completion.TrySetResult();
            return true;
        }

        if (!TryBuildOutboundStreamPayload(
                streamId,
                writeOffset,
                committedStreamData,
                finishWrites,
                out byte[] streamPayload,
                out int streamPayloadLength))
        {
            pendingStreamActionRequests.Remove(requestId);
            return FailWriteAfterRollback(
                completion,
                sendStateBeforeWrite,
                new InvalidOperationException("The connection runtime could not build the stream write payload."));
        }

        completion.ReleaseOwnedStreamData();

        if (!streamRegistry.Bookkeeping.TryGetStreamPriority(streamId, out int streamPriority))
        {
            streamPriority = 0;
        }

        if (sendRuntime.HasPendingRetransmission(QuicPacketNumberSpace.ApplicationData))
        {
            LogApplicationSend(
                $"app-tx branch=pending-retransmission role={tlsState.Role} stream={streamId} queue={applicationSendQueue.Count}.");
            QueuePendingApplicationSend(
                streamId,
                streamPriority,
                streamPayload,
                streamPayloadLength,
                nowTicks,
                tryFlushPendingApplicationSendsAfterEnqueue: true,
                ref effects);
            _ = TryFlushPendingRetransmissions(
                QuicPacketNumberSpace.ApplicationData,
                nowTicks,
                probePacket: false,
                ref effects);
            AppendLifecycleTimerEffects(ref effects);
            pendingStreamActionRequests.Remove(requestId);
            completion.TrySetResult();
            return true;
        }

        int maximumApplicationPayloadBytes = GetMaximumQueuedApplicationPayloadBytes();
        if (streamPayloadLength > maximumApplicationPayloadBytes)
        {
            LogApplicationSend(
                $"app-tx branch=oversized-queue role={tlsState.Role} stream={streamId} payloadLength={streamPayloadLength} budget={maximumApplicationPayloadBytes} queue={applicationSendQueue.Count}.");
            QueuePendingApplicationSend(
                streamId,
                streamPriority,
                streamPayload,
                streamPayloadLength,
                nowTicks,
                tryFlushPendingApplicationSendsAfterEnqueue: true,
                ref effects);
            pendingStreamActionRequests.Remove(requestId);
            completion.TrySetResult();
            return true;
        }

        if (!finishWrites
            && committedStreamDataLength > 0
            && (activePath?.AmplificationState.IsAddressValidated ?? false)
            && (applicationSendQueue.Count > 0
                || committedStreamDataLength < ApplicationSendDelayThresholdBytes))
        {
            LogApplicationSend(
                $"app-tx branch=delay-small-write role={tlsState.Role} stream={streamId} queue={applicationSendQueue.Count}.");
            QueuePendingApplicationSend(
                streamId,
                streamPriority,
                streamPayload,
                streamPayloadLength,
                nowTicks,
                tryFlushPendingApplicationSendsAfterEnqueue: false,
                ref effects);
            pendingStreamActionRequests.Remove(requestId);
            completion.TrySetResult();
            return true;
        }

        LogApplicationSend(
            $"app-tx branch=direct-send role={tlsState.Role} stream={streamId} payloadLength={streamPayloadLength} queue={applicationSendQueue.Count}.");

        Exception? exception = null;
        if (!TryProtectAndAccountStreamApplicationPayload(
            streamPayload.AsMemory(0, streamPayloadLength),
            streamPayload,
            "The connection runtime could not protect the stream write packet.",
            StreamWriteSendBlockedMessage,
            probePacket: false,
            streamId: streamId,
            streamIds: null,
            ref effects,
            out QuicConnectionPathIdentity sendPathIdentity,
            out ReadOnlyMemory<byte> protectedPacket,
            out exception))
        {
            if (IsTransientApplicationSendPathBlocked(exception))
            {
                LogApplicationSend(
                    $"app-tx branch=direct-send-blocked role={tlsState.Role} stream={streamId} length={streamPayloadLength} reason={exception?.Message}.");
                QueuePendingApplicationSend(
                    streamId,
                    streamPriority,
                    streamPayload,
                    streamPayloadLength,
                    nowTicks,
                    tryFlushPendingApplicationSendsAfterEnqueue: true,
                    ref effects,
                    out Exception? queuedFlushException);
                pendingStreamActionRequests.Remove(requestId);
                if (queuedFlushException is not null && !IsTransientApplicationSendPathBlocked(queuedFlushException))
                {
                    return false;
                }

                completion.TrySetResult();
                return true;
            }

            QuicBufferPool.ReturnBytes(streamPayload);
            pendingStreamActionRequests.Remove(requestId);
            return FailWriteAfterRollback(
                completion,
                sendStateBeforeWrite,
                exception!);
        }

        AppendSendDatagramEffect(ref effects, sendPathIdentity, protectedPacket);

        LogApplicationSend(
            $"app-tx sent role={tlsState.Role} stream={streamId} packet={protectedPacket.Length} fin={finishWrites} queue={applicationSendQueue.Count}.");

        if (finishWrites)
        {
            TryReleasePeerStreamCapacity(streamId, ref effects);
        }

        AppendLifecycleTimerEffects(ref effects);
        pendingStreamActionRequests.Remove(requestId);
        completion.TrySetResult();
        return true;
    }

    private bool TryFlushFragmentedQueuedApplicationSend(
        PendingApplicationSendRequest queuedWrite,
        QuicStreamFrame queuedFrame,
        int fragmentDataLength,
        long nowTicks,
        ref QuicConnectionEffectAccumulator effects,
        out Exception? exception)
    {
        exception = null;

        if (fragmentDataLength <= 0
            || fragmentDataLength > queuedFrame.StreamDataLength)
        {
            exception = new InvalidOperationException("The connection runtime could not split the queued stream write packet.");
            return false;
        }

        if (!TryBuildOutboundStreamPayload(
                queuedFrame.StreamId.Value,
                queuedFrame.Offset,
                queuedFrame.StreamData[..fragmentDataLength],
                fin: false,
                out byte[] fragmentPayload,
                out int fragmentPayloadLength))
        {
            exception = new InvalidOperationException("The connection runtime could not build the queued stream write fragment.");
            return false;
        }

        byte[]? remainderPayload = null;
        int remainderPayloadLength = 0;
        if (fragmentDataLength < queuedFrame.StreamDataLength
            && !TryBuildOutboundStreamPayload(
                queuedFrame.StreamId.Value,
                queuedFrame.Offset + (ulong)fragmentDataLength,
                queuedFrame.StreamData[fragmentDataLength..],
                fin: queuedFrame.IsFin,
                out remainderPayload,
                out remainderPayloadLength))
        {
            QuicBufferPool.ReturnBytes(fragmentPayload);
            exception = new InvalidOperationException("The connection runtime could not build the queued stream write remainder.");
            return false;
        }

        if (!TryProtectAndAccountStreamApplicationPayload(
                fragmentPayload.AsMemory(0, fragmentPayloadLength),
                fragmentPayload,
                "The connection runtime could not protect the queued stream write packet.",
                QueuedStreamWriteSendBlockedMessage,
                probePacket: false,
                streamId: queuedWrite.StreamId,
                streamIds: null,
                ref effects,
                out QuicConnectionPathIdentity sendPathIdentity,
                out ReadOnlyMemory<byte> protectedPacket,
                out exception))
        {
            QuicBufferPool.ReturnBytes(fragmentPayload);
            if (remainderPayload is not null)
            {
                QuicBufferPool.ReturnBytes(remainderPayload);
            }

            return false;
        }

        if (remainderPayload is not null)
        {
            if (!applicationSendQueue.TryReplaceQueuedWritePayload(
                    queuedWrite.Sequence,
                    remainderPayload,
                    remainderPayloadLength))
            {
                QuicBufferPool.ReturnBytes(remainderPayload);
                throw new InvalidOperationException("The connection runtime could not update the queued stream write after a partial send.");
            }
        }
        else if (!applicationSendQueue.TryRemoveQueuedWrite(queuedWrite.Sequence, returnPayloads: true))
        {
            throw new InvalidOperationException("The connection runtime could not remove the completed queued stream write.");
        }

        AppendSendDatagramEffect(ref effects, sendPathIdentity, protectedPacket);

        pendingApplicationSendDelayDueTicks = applicationSendQueue.Count > 0
            ? SaturatingAdd(nowTicks, ConvertMicrosToTicks(ApplicationSendDelayMicros))
            : null;
        AppendLifecycleTimerEffects(ref effects);

        exception = null;
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
        QuicConnectionRuntime.StreamActionRequestCompletionSource completion,
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

    private void QueuePendingApplicationSend(
        ulong streamId,
        int priority,
        byte[] streamPayload,
        int streamPayloadLength,
        long nowTicks,
        bool tryFlushPendingApplicationSendsAfterEnqueue,
        ref QuicConnectionEffectAccumulator effects)
        => QueuePendingApplicationSend(
            streamId,
            priority,
            streamPayload,
            streamPayloadLength,
            nowTicks,
            tryFlushPendingApplicationSendsAfterEnqueue,
            ref effects,
            out _);

    private void QueuePendingApplicationSend(
        ulong streamId,
        int priority,
        byte[] streamPayload,
        int streamPayloadLength,
        long nowTicks,
        bool tryFlushPendingApplicationSendsAfterEnqueue,
        ref QuicConnectionEffectAccumulator effects,
        out Exception? flushException)
    {
        flushException = null;
        applicationSendQueue.Enqueue(streamId, priority, streamPayload, streamPayloadLength);

        if (applicationSendQueue.Count == 1)
        {
            pendingApplicationSendDelayDueTicks = SaturatingAdd(
                nowTicks,
                ConvertMicrosToTicks(ApplicationSendDelayMicros));
        }

        LogApplicationSend(
            $"app-tx queue-updated role={tlsState.Role} stream={streamId} length={streamPayloadLength} queue={applicationSendQueue.Count} dueTicks={(pendingApplicationSendDelayDueTicks?.ToString() ?? "null")}.");

        AppendLifecycleTimerEffects(ref effects);
        if (tryFlushPendingApplicationSendsAfterEnqueue)
        {
            _ = TryFlushPendingApplicationSendsAfterRecoveryProgress(nowTicks, ref effects, out flushException);
        }
    }

    private bool TryPromoteQueuedApplicationSendToFinal(ulong streamId)
    {
        // CONTEXT: When a caller finishes with no new bytes, the latest queued write must be upgraded
        // in place to carry FIN so the stream's byte offsets and pending send order stay consistent.
        // Rebuilding the queued payload here avoids emitting a separate empty FIN packet for the same
        // stream state.
        // SEE: code:src/Incursa.Quic/QuicConnectionRuntime.Streams.cs#HandleWriteStreamAction
        // SEE: code:src/Incursa.Quic/QuicConnectionRuntime.Streams.cs#FlushPendingApplicationSends
        if (!applicationSendQueue.TryGetLatestQueuedWriteForStream(streamId, out PendingApplicationSendRequest queuedWrite))
        {
            return false;
        }

        if (!QuicStreamParser.TryParseStreamFrame(
                queuedWrite.StreamPayload.AsSpan(0, queuedWrite.StreamPayloadLength),
                out QuicStreamFrame frame)
            || !TryBuildOutboundStreamPayload(
                streamId,
                frame.Offset,
                frame.StreamData,
                fin: true,
                out byte[] finalPayload,
                out int finalPayloadLength))
        {
            return false;
        }

        if (!applicationSendQueue.TryReplaceQueuedWritePayload(
                queuedWrite.Sequence,
                finalPayload,
                finalPayloadLength))
        {
            QuicBufferPool.ReturnBytes(finalPayload);
            return false;
        }

        return true;
    }

    private bool FlushPendingApplicationSends(long nowTicks, ref QuicConnectionEffectAccumulator effects)
        => FlushPendingApplicationSends(nowTicks, ref effects, out _);

    private bool FlushPendingApplicationSends(
        long nowTicks,
        ref QuicConnectionEffectAccumulator effects,
        out Exception? exception)
        => FlushPendingApplicationSends(nowTicks, probePacket: false, ref effects, out exception);

    private bool FlushPendingApplicationSends(
        long nowTicks,
        bool probePacket,
        ref QuicConnectionEffectAccumulator effects)
        => FlushPendingApplicationSends(nowTicks, probePacket, ref effects, out _);

    private bool FlushPendingApplicationSends(
        long nowTicks,
        bool probePacket,
        ref QuicConnectionEffectAccumulator effects,
        out Exception? exception)
        => FlushPendingApplicationSends(
            nowTicks,
            probePacket,
            QuicQueuedApplicationSendBudget.AllowSingleDatagram(GetMaximumQueuedApplicationPayloadBytes()),
            ref effects,
            out exception);

    private bool FlushPendingApplicationSends(
        long nowTicks,
        bool probePacket,
        QuicQueuedApplicationSendBudget schedulerBudget,
        ref QuicConnectionEffectAccumulator effects,
        out Exception? exception)
    {
        bool measureFlushes = RuntimeWorkItemFlushMeasurementEnabled;
        int applicationSendCountBefore = measureFlushes ? applicationSendQueue.Count : 0;
        if (applicationSendQueue.Count == 0)
        {
            pendingApplicationSendDelayDueTicks = null;
            exception = null;
            return false;
        }

        LogApplicationSend(
            $"app-tx flush-start role={tlsState.Role} queue={applicationSendQueue.Count} probe={probePacket} hasOnlyQueuedWrite={applicationSendQueue.Count == 1}.");

        ReadOnlyMemory<byte> combinedPayload = default;
        ulong? payloadStreamId = null;
        ulong[]? streamIds = null;
        PendingApplicationSendRequest onlyQueuedWrite = default;
        PendingApplicationSendRequest[]? queuedWrites = null;
        byte[]? combinedPayloadOwner = null;
        ReadOnlySpan<PendingApplicationSendRequest> selectedWrites = default;
        bool hasOnlyQueuedWrite = applicationSendQueue.TryGetOnlyQueuedWrite(out onlyQueuedWrite);

        try
        {
            if (hasOnlyQueuedWrite)
            {
                QuicApplicationSendPlan sendPlan = QuicApplicationSendScheduler.SelectQueuedApplicationSendPlan(
                    onlyQueuedWrite,
                    schedulerBudget,
                    out QuicStreamFrame onlyQueuedWriteFrame,
                    out exception);
                if (sendPlan.Kind == QuicApplicationSendPlanKind.None)
                {
                    return false;
                }

                if (sendPlan.Kind == QuicApplicationSendPlanKind.Fragment)
                {
                    if (TryFlushFragmentedQueuedApplicationSend(
                            onlyQueuedWrite,
                            onlyQueuedWriteFrame,
                            sendPlan.FragmentDataLength,
                            nowTicks,
                            ref effects,
                            out exception))
                    {
                        LogApplicationSend(
                            $"app-tx flush-fragment-sent role={tlsState.Role} stream={onlyQueuedWrite.StreamId} queue={applicationSendQueue.Count}.");
                        exception = null;
                        return true;
                    }

                    if (IsTransientApplicationSendPathBlocked(exception))
                    {
                        pendingApplicationSendDelayDueTicks = SaturatingAdd(
                            nowTicks,
                            ConvertMicrosToTicks(ApplicationSendDelayMicros));
                        AppendLifecycleTimerEffects(ref effects);
                        LogApplicationSend(
                            $"app-tx flush-fragment-blocked role={tlsState.Role} stream={onlyQueuedWrite.StreamId} queue={applicationSendQueue.Count} reason={exception?.Message}.");
                    }

                    return false;
                }

                combinedPayload = onlyQueuedWrite.StreamPayload.AsMemory(0, onlyQueuedWrite.StreamPayloadLength);
                payloadStreamId = onlyQueuedWrite.StreamId;
            }
            else
            {
                if (!applicationSendQueue.TryGetNextQueuedWrite(out PendingApplicationSendRequest nextQueuedWrite))
                {
                    exception = null;
                    return false;
                }

                QuicApplicationSendPlan nextWritePlan = QuicApplicationSendScheduler.SelectQueuedApplicationSendPlan(
                    nextQueuedWrite,
                    schedulerBudget,
                    out QuicStreamFrame nextQueuedWriteFrame,
                    out exception);
                if (nextWritePlan.Kind == QuicApplicationSendPlanKind.None)
                {
                    return false;
                }

                if (nextWritePlan.Kind == QuicApplicationSendPlanKind.Fragment)
                {
                    if (TryFlushFragmentedQueuedApplicationSend(
                            nextQueuedWrite,
                            nextQueuedWriteFrame,
                            nextWritePlan.FragmentDataLength,
                            nowTicks,
                            ref effects,
                            out exception))
                    {
                        LogApplicationSend(
                            $"app-tx flush-fragment-sent role={tlsState.Role} stream={nextQueuedWrite.StreamId} queue={applicationSendQueue.Count}.");
                        exception = null;
                        return true;
                    }

                    if (IsTransientApplicationSendPathBlocked(exception))
                    {
                        pendingApplicationSendDelayDueTicks = SaturatingAdd(
                            nowTicks,
                            ConvertMicrosToTicks(ApplicationSendDelayMicros));
                        AppendLifecycleTimerEffects(ref effects);
                        LogApplicationSend(
                            $"app-tx flush-fragment-blocked role={tlsState.Role} stream={nextQueuedWrite.StreamId} queue={applicationSendQueue.Count} reason={exception?.Message}.");
                    }

                    return false;
                }

                queuedWrites = applicationSendQueue.RentSortedQueuedWrites(out int queuedWriteCount);
                ReadOnlySpan<PendingApplicationSendRequest> sortedQueuedWrites =
                    queuedWrites.AsSpan(0, queuedWriteCount);

                QuicApplicationSendPlan sendPlan = QuicApplicationSendScheduler.SelectQueuedApplicationSendPlan(
                    sortedQueuedWrites,
                    schedulerBudget,
                    out QuicStreamFrame firstSelectedWriteFrame,
                    out exception);
                if (sendPlan.Kind == QuicApplicationSendPlanKind.None)
                {
                    return false;
                }

                selectedWrites = sortedQueuedWrites[..sendPlan.SelectedWriteCount];

                if (sendPlan.Kind == QuicApplicationSendPlanKind.Fragment)
                {
                    if (TryFlushFragmentedQueuedApplicationSend(
                            selectedWrites[0],
                            firstSelectedWriteFrame,
                            sendPlan.FragmentDataLength,
                            nowTicks,
                            ref effects,
                            out exception))
                    {
                        LogApplicationSend(
                            $"app-tx flush-fragment-sent role={tlsState.Role} stream={selectedWrites[0].StreamId} queue={applicationSendQueue.Count}.");
                        exception = null;
                        return true;
                    }

                    if (IsTransientApplicationSendPathBlocked(exception))
                    {
                        pendingApplicationSendDelayDueTicks = SaturatingAdd(
                            nowTicks,
                            ConvertMicrosToTicks(ApplicationSendDelayMicros));
                        AppendLifecycleTimerEffects(ref effects);
                        LogApplicationSend(
                            $"app-tx flush-fragment-blocked role={tlsState.Role} stream={selectedWrites[0].StreamId} queue={applicationSendQueue.Count} reason={exception?.Message}.");
                    }

                    return false;
                }

                int combinedPayloadLength = 0;
                foreach (PendingApplicationSendRequest queuedWrite in selectedWrites)
                {
                    combinedPayloadLength = checked(combinedPayloadLength + queuedWrite.StreamPayloadLength);
                }

                combinedPayloadOwner = QuicBufferPool.RentBytes(combinedPayloadLength);
                int copyOffset = 0;
                foreach (PendingApplicationSendRequest queuedWrite in selectedWrites)
                {
                    queuedWrite.StreamPayload.AsSpan(0, queuedWrite.StreamPayloadLength)
                        .CopyTo(combinedPayloadOwner.AsSpan(copyOffset));
                    copyOffset += queuedWrite.StreamPayloadLength;
                }

                combinedPayload = combinedPayloadOwner.AsMemory(0, combinedPayloadLength);
                if (QuicApplicationSendQueue.TryGetOnlyDistinctStreamId(selectedWrites, out ulong onlyStreamId))
                {
                    payloadStreamId = onlyStreamId;
                }
                else
                {
                    streamIds = QuicApplicationSendQueue.BuildDistinctStreamIds(selectedWrites);
                }
            }

            QuicMetrics.RecordApplicationSendBatchStreams(
                tlsState.Role,
                payloadStreamId.HasValue ? 1 : streamIds?.Length ?? 0,
                combinedWrite: !hasOnlyQueuedWrite);

            if (!TryProtectAndAccountStreamApplicationPayload(
                combinedPayload,
                hasOnlyQueuedWrite ? onlyQueuedWrite.StreamPayload : combinedPayloadOwner,
                "The connection runtime could not protect the queued stream write packet.",
                QueuedStreamWriteSendBlockedMessage,
                probePacket,
                streamId: payloadStreamId,
                streamIds: streamIds,
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
                    AppendLifecycleTimerEffects(ref effects);
                    LogApplicationSend(
                        $"app-tx flush-blocked role={tlsState.Role} queue={applicationSendQueue.Count} reason={exception?.Message}.");
                }

                return false;
            }

            if (hasOnlyQueuedWrite)
            {
                applicationSendQueue.TryRemoveQueuedWritesForStream(onlyQueuedWrite.StreamId);
            }
            else
            {
                combinedPayloadOwner = null;
                applicationSendQueue.TryRemoveQueuedWrites(selectedWrites);
            }

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

            AppendSendDatagramEffect(ref effects,
                sendPathIdentity,
                protectedPacket);
            AppendLifecycleTimerEffects(ref effects);
            LogApplicationSend(
                $"app-tx flush-sent role={tlsState.Role} packet={protectedPacket.Length} queue={applicationSendQueue.Count}.");
            exception = null;
            return true;
        }
        finally
        {
            if (measureFlushes)
            {
                runtimeWorkItemFlushedApplicationSends += Math.Max(
                    0,
                    applicationSendCountBefore - applicationSendQueue.Count);
            }

            if (combinedPayloadOwner is not null)
            {
                QuicBufferPool.ReturnBytes(combinedPayloadOwner);
            }

            if (queuedWrites is not null)
            {
                QuicApplicationSendQueue.ReturnRentedQueuedWrites(queuedWrites);
            }
        }
    }

    private bool TryProtectAndAccountStreamApplicationPayload(
        ReadOnlyMemory<byte> payload,
        byte[]? plaintextPayloadOwner,
        string protectFailureMessage,
        string amplificationFailureMessage,
        bool probePacket,
        ulong? streamId,
        ulong[]? streamIds,
        ref QuicConnectionEffectAccumulator effects,
        out QuicConnectionPathIdentity sendPathIdentity,
        out ReadOnlyMemory<byte> protectedPacket,
        out Exception? exception)
    {
        sendPathIdentity = default;
        protectedPacket = ReadOnlyMemory<byte>.Empty;

        LogApplicationSend(
            $"app-tx protect-start role={tlsState.Role} payload={payload.Length} probe={probePacket} streamId={(streamId.HasValue ? streamId.Value.ToString() : "null")} streamIds={(streamIds is null ? "null" : streamIds.Length.ToString())}.");

        if (activePath is null)
        {
            exception = new InvalidOperationException("The connection has no active path.");
            LogApplicationSend($"app-tx protect-blocked role={tlsState.Role} reason={exception.Message}.");
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
            streamId: streamId,
            streamIds: streamIds,
            plaintextPayloadOwner: plaintextPayloadOwner,
            enforcePathMaximumDatagramSize: true);
    }

    private bool TryFlushPendingApplicationSendsAfterRecoveryProgress(
        long nowTicks,
        ref QuicConnectionEffectAccumulator effects)
        => TryFlushPendingApplicationSendsAfterRecoveryProgress(nowTicks, ref effects, out _);

    private bool TryFlushPendingApplicationSendsAfterRecoveryProgress(
        long nowTicks,
        ref QuicConnectionEffectAccumulator effects,
        out Exception? exception)
    {
        exception = null;
        bool stateChanged = false;
        for (int flushCount = 0; applicationSendQueue.Count > 0; flushCount++)
        {
            QuicQueuedApplicationSendBudget sendBudget = QuicSendPolicy.ComputeQueuedApplicationSendBudget(
                CaptureQueuedApplicationSendPolicySnapshot());
            if (!sendBudget.CanSendQueuedApplicationData || flushCount >= sendBudget.MaxDatagrams)
            {
                break;
            }

            if (!FlushPendingApplicationSends(
                    nowTicks,
                    probePacket: false,
                    sendBudget,
                    ref effects,
                    out Exception? flushException))
            {
                exception = flushException;
                break;
            }

            stateChanged = true;
            if (sendRuntime.HasPendingRetransmission(QuicPacketNumberSpace.ApplicationData))
            {
                break;
            }
        }

        stateChanged |= TryFlushPendingFlowControlCreditUpdates(ref effects);
        stateChanged |= TryFlushPendingPeerStreamCapacityReleases(ref effects);
        return stateChanged;
    }

    private QuicSendPolicySnapshot CaptureQueuedApplicationSendPolicySnapshot()
    {
        QuicConnectionPathRecoverySnapshot recoverySnapshot = sendRuntime.CapturePathRecoverySnapshot();
        if (activePath is not { } currentPath)
        {
            return new QuicSendPolicySnapshot(
                HasActivePath: false,
                CanSendOrdinaryPackets: false,
                MaximumDatagramSizeBytes: 0,
                MaximumApplicationPayloadBytes: GetMaximumQueuedApplicationPayloadBytes(),
                CongestionWindowBytes: recoverySnapshot.CongestionWindowBytes,
                BytesInFlightBytes: recoverySnapshot.BytesInFlightBytes,
                PendingRetransmissionCount: sendRuntime.PendingRetransmissionCount,
                HasApplicationDataRetransmission: sendRuntime.HasPendingRetransmission(QuicPacketNumberSpace.ApplicationData),
                AntiAmplificationAvailableBytes: 0,
                IsAddressValidated: false,
                HandshakeConfirmed: HandshakeConfirmed,
                HasOneRttProtection: tlsState.OneRttProtectPacketProtectionMaterial.HasValue,
                QueuedApplicationSendCount: applicationSendQueue.Count);
        }

        return new QuicSendPolicySnapshot(
            HasActivePath: true,
            CanSendOrdinaryPackets: CanSendOrdinaryPackets
                && currentPath.MaximumDatagramSizeState.CanSendOrdinaryPackets,
            MaximumDatagramSizeBytes: currentPath.MaximumDatagramSizeState.MaximumDatagramSizeBytes,
            MaximumApplicationPayloadBytes: GetMaximumQueuedApplicationPayloadBytes(),
            CongestionWindowBytes: recoverySnapshot.CongestionWindowBytes,
            BytesInFlightBytes: recoverySnapshot.BytesInFlightBytes,
            PendingRetransmissionCount: sendRuntime.PendingRetransmissionCount,
            HasApplicationDataRetransmission: sendRuntime.HasPendingRetransmission(QuicPacketNumberSpace.ApplicationData),
            AntiAmplificationAvailableBytes: currentPath.AmplificationState.RemainingSendBudget,
            IsAddressValidated: currentPath.AmplificationState.IsAddressValidated,
            HandshakeConfirmed: HandshakeConfirmed,
            HasOneRttProtection: tlsState.OneRttProtectPacketProtectionMaterial.HasValue,
            QueuedApplicationSendCount: applicationSendQueue.Count);
    }

    private static bool IsTransientCongestionExhaustion(Exception? exception)
    {
        return exception is InvalidOperationException invalidOperationException
            && string.Equals(
                invalidOperationException.Message,
                CongestionControllerExhaustedMessage,
                StringComparison.Ordinal);
    }

    private static Exception MaterializeApplicationSendException(Exception exception)
    {
        return ReferenceEquals(exception, CongestionControllerExhaustedException)
            ? new InvalidOperationException(CongestionControllerExhaustedMessage)
            : exception;
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

    private void TryRemoveQueuedApplicationSendsForStream(ulong streamId, ref QuicConnectionEffectAccumulator effects)
    {
        if (!applicationSendQueue.TryRemoveQueuedWritesForStream(streamId, returnPayloads: true))
        {
            return;
        }

        if (applicationSendQueue.Count == 0)
        {
            pendingApplicationSendDelayDueTicks = null;
            AppendLifecycleTimerEffects(ref effects);
        }
    }

    private int GetMaximumQueuedApplicationPayloadBytes()
        => GetMaximumApplicationPayloadBytes(ApplicationSendBatchAckHeadroomBytes);

    private int GetMaximumFlowControlCreditPayloadBytes()
    {
        int ackHeadroomBytes = 0;
        QuicAckFrame? ackFrame = null;
        try
        {
            ulong nowMicros = GetElapsedMicros(lastTransitionTicks);
            if (sendRuntime.FlowController.ShouldIncludeAckFrameWithOutgoingPacket(
                    QuicPacketNumberSpace.ApplicationData,
                    nowMicros,
                    maxAckDelayMicros: 0)
                && sendRuntime.FlowController.TryBuildAckFrame(
                    QuicPacketNumberSpace.ApplicationData,
                    nowMicros,
                    out ackFrame)
                && QuicFrameCodec.TryGetAckFramePayloadLength(ackFrame, out int ackPayloadLength))
            {
                ackHeadroomBytes = ackPayloadLength;
            }
        }
        finally
        {
            ackFrame?.Dispose();
        }

        return GetMaximumApplicationPayloadBytes(ackHeadroomBytes);
    }

    private int GetMaximumApplicationPayloadBytes(int ackHeadroomBytes)
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
        ulong reservedBytes = (ulong)(shortHeaderOverheadBytes + ackHeadroomBytes);
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
        ref QuicConnectionEffectAccumulator effects)
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
        ref QuicConnectionEffectAccumulator effects)
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

    private bool TryDeferFlowControlCreditUpdate(
        QuicMaxDataFrame? maxDataFrame,
        QuicMaxStreamDataFrame? maxStreamDataFrame)
    {
        bool deferred = false;
        if (maxDataFrame is { } connectionCredit
            && (!pendingFlowControlConnectionCreditFrame.HasValue
                || connectionCredit.MaximumData > pendingFlowControlConnectionCreditFrame.Value.MaximumData))
        {
            pendingFlowControlConnectionCreditFrame = connectionCredit;
            deferred = true;
        }

        if (maxStreamDataFrame is { } streamCredit
            && (!pendingFlowControlStreamCreditFrames.TryGetValue(streamCredit.StreamId, out QuicMaxStreamDataFrame pendingStreamCredit)
                || streamCredit.MaximumStreamData > pendingStreamCredit.MaximumStreamData))
        {
            pendingFlowControlStreamCreditFrames[streamCredit.StreamId] = streamCredit;
            deferred = true;
        }

        return deferred;
    }

    private bool TryFlushPendingFlowControlCreditUpdates(ref QuicConnectionEffectAccumulator effects)
    {
        bool measureFlushes = RuntimeWorkItemFlushMeasurementEnabled;
        int countBefore = 0;
        if (measureFlushes)
        {
            countBefore = pendingFlowControlStreamCreditFrames.Count;
            if (pendingFlowControlConnectionCreditFrame.HasValue)
            {
                countBefore++;
            }
        }
        try
        {
            return TryFlushPendingFlowControlCreditUpdatesCore(ref effects);
        }
        finally
        {
            if (measureFlushes)
            {
                int countAfter = pendingFlowControlStreamCreditFrames.Count;
                if (pendingFlowControlConnectionCreditFrame.HasValue)
                {
                    countAfter++;
                }

                runtimeWorkItemFlushedFlowControlUpdates += Math.Max(0, countBefore - countAfter);
            }
        }
    }

    private bool TryFlushPendingFlowControlCreditUpdatesCore(ref QuicConnectionEffectAccumulator effects)
    {
        if (!pendingFlowControlConnectionCreditFrame.HasValue
            && pendingFlowControlStreamCreditFrames.Count == 0)
        {
            return false;
        }

        bool stateChanged = false;
        if (pendingFlowControlConnectionCreditFrame is { } connectionCredit
            && pendingFlowControlStreamCreditFrames.Count > 0)
        {
            Dictionary<ulong, QuicMaxStreamDataFrame>.Enumerator streamCreditEnumerator =
                pendingFlowControlStreamCreditFrames.GetEnumerator();
            _ = streamCreditEnumerator.MoveNext();
            KeyValuePair<ulong, QuicMaxStreamDataFrame> streamCredit = streamCreditEnumerator.Current;
            if (!TrySendFlowControlCreditUpdate(
                    connectionCredit,
                    streamCredit.Value,
                    "The connection runtime could not protect the combined flow-control credit packet.",
                    "The connection cannot send the combined flow-control credit packet.",
                    ref effects))
            {
                return stateChanged;
            }

            pendingFlowControlConnectionCreditFrame = null;
            pendingFlowControlStreamCreditFrames.Remove(streamCredit.Key);
            stateChanged = true;
        }

        if (pendingFlowControlConnectionCreditFrame is { } remainingConnectionCredit)
        {
            if (!TrySendFlowControlCreditUpdate(
                    remainingConnectionCredit,
                    "The connection runtime could not protect the MAX_DATA packet.",
                    "The connection cannot send the MAX_DATA packet.",
                    ref effects))
            {
                return stateChanged;
            }

            pendingFlowControlConnectionCreditFrame = null;
            stateChanged = true;
        }

        KeyValuePair<ulong, QuicMaxStreamDataFrame>[]? streamCredits = null;
        int streamCreditCount = pendingFlowControlStreamCreditFrames.Count;
        if (streamCreditCount > 0)
        {
            streamCredits = ArrayPool<KeyValuePair<ulong, QuicMaxStreamDataFrame>>.Shared.Rent(streamCreditCount);
            int index = 0;
            foreach (KeyValuePair<ulong, QuicMaxStreamDataFrame> streamCredit in pendingFlowControlStreamCreditFrames)
            {
                streamCredits[index++] = streamCredit;
            }

            index = 0;
            try
            {
                while (index < streamCreditCount)
                {
                    if (!TrySendFlowControlCreditUpdates(
                            streamCredits.AsSpan(index, streamCreditCount - index),
                            out int sentCreditCount,
                            ref effects))
                    {
                        break;
                    }

                    for (int sentIndex = 0; sentIndex < sentCreditCount; sentIndex++)
                    {
                        pendingFlowControlStreamCreditFrames.Remove(streamCredits[index + sentIndex].Key);
                    }

                    index += sentCreditCount;
                    stateChanged = true;
                }
            }
            finally
            {
                ArrayPool<KeyValuePair<ulong, QuicMaxStreamDataFrame>>.Shared.Return(
                    streamCredits,
                    clearArray: true);
            }
        }

        return stateChanged;
    }

    private bool TrySendFlowControlCreditUpdates(
        ReadOnlySpan<KeyValuePair<ulong, QuicMaxStreamDataFrame>> streamCredits,
        out int sentCreditCount,
        ref QuicConnectionEffectAccumulator effects)
    {
        sentCreditCount = 0;
        byte[]? payloadOwner = null;
        if (!TryBuildOutboundMaxStreamDataPayload(
                streamCredits,
                out ReadOnlyMemory<byte> payload,
                out payloadOwner,
                out int payloadCreditCount))
        {
            return false;
        }

        try
        {
            if (!TryProtectAndAccountApplicationPayload(
                payload,
                "The connection runtime could not protect the MAX_STREAM_DATA packet.",
                "The connection cannot send the MAX_STREAM_DATA packet.",
                ref effects,
                out QuicConnectionActivePathRecord currentPath,
                out QuicConnectionPathAmplificationState updatedAmplificationState,
                out ReadOnlyMemory<byte> protectedPacket,
                out Exception? exception,
                plaintextPayloadOwner: payloadOwner))
            {
                _ = exception;
                return false;
            }

            payloadOwner = null;
            activePath = currentPath with
            {
                AmplificationState = updatedAmplificationState,
            };

            AppendSendDatagramEffect(ref effects, currentPath.Identity, protectedPacket);
            sentCreditCount = payloadCreditCount;
            return true;
        }
        finally
        {
            if (payloadOwner is not null)
            {
                QuicBufferPool.ReturnBytes(payloadOwner);
            }
        }
    }

    private bool TrySendFlowControlCreditUpdate(
        QuicMaxDataFrame frame,
        string protectFailureMessage,
        string amplificationFailureMessage,
        ref QuicConnectionEffectAccumulator effects)
    {
        byte[]? payloadOwner = null;
        if (!TryBuildOutboundMaxDataPayload(frame, out ReadOnlyMemory<byte> payload, out payloadOwner))
        {
            return false;
        }

        try
        {
            if (!TryProtectAndAccountApplicationPayload(
                payload,
                protectFailureMessage,
                amplificationFailureMessage,
                ref effects,
                out QuicConnectionActivePathRecord currentPath,
                out QuicConnectionPathAmplificationState updatedAmplificationState,
                out ReadOnlyMemory<byte> protectedPacket,
                out Exception? exception,
                plaintextPayloadOwner: payloadOwner))
            {
                _ = exception;
                return false;
            }

            payloadOwner = null;

            activePath = currentPath with
            {
                AmplificationState = updatedAmplificationState,
            };

            AppendSendDatagramEffect(ref effects,
                currentPath.Identity,
                protectedPacket);
            return true;
        }
        finally
        {
            if (payloadOwner is not null)
            {
                QuicBufferPool.ReturnBytes(payloadOwner);
            }
        }
    }

    private bool TrySendFlowControlCreditUpdate(
        QuicMaxDataFrame maxDataFrame,
        QuicMaxStreamDataFrame maxStreamDataFrame,
        string protectFailureMessage,
        string amplificationFailureMessage,
        ref QuicConnectionEffectAccumulator effects)
    {
        byte[]? payloadOwner = null;
        if (!TryBuildOutboundFlowControlCreditPayload(
                maxDataFrame,
                maxStreamDataFrame,
                out ReadOnlyMemory<byte> payload,
                out payloadOwner))
        {
            return false;
        }

        try
        {
            if (!TryProtectAndAccountApplicationPayload(
                payload,
                protectFailureMessage,
                amplificationFailureMessage,
                ref effects,
                out QuicConnectionActivePathRecord currentPath,
                out QuicConnectionPathAmplificationState updatedAmplificationState,
                out ReadOnlyMemory<byte> protectedPacket,
                out Exception? exception,
                plaintextPayloadOwner: payloadOwner))
            {
                _ = exception;
                return false;
            }

            payloadOwner = null;

            activePath = currentPath with
            {
                AmplificationState = updatedAmplificationState,
            };

            AppendSendDatagramEffect(ref effects,
                currentPath.Identity,
                protectedPacket);
            return true;
        }
        finally
        {
            if (payloadOwner is not null)
            {
                QuicBufferPool.ReturnBytes(payloadOwner);
            }
        }
    }

    private bool TrySendFlowControlBlockedSignal(
        QuicDataBlockedFrame frame,
        string protectFailureMessage,
        string amplificationFailureMessage,
        ref QuicConnectionEffectAccumulator effects)
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
        ref QuicConnectionEffectAccumulator effects)
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
        ref QuicConnectionEffectAccumulator effects)
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
        ref QuicConnectionEffectAccumulator effects)
    {
        if (!TryRemovePendingStreamActionRequest(requestId, out QuicConnectionRuntime.StreamActionRequestCompletionSource completion))
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
            completion.TrySetException(MaterializeApplicationSendException(exception!));
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

        completion.TrySetResult();
        return true;
    }

    private bool HandleStopSendingStreamAction(
        long requestId,
        ulong streamId,
        ulong applicationErrorCode,
        ref QuicConnectionEffectAccumulator effects)
    {
        if (!TryRemovePendingStreamActionRequest(requestId, out QuicConnectionRuntime.StreamActionRequestCompletionSource completion))
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
            completion.TrySetResult();
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
            completion.TrySetException(MaterializeApplicationSendException(exception!));
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

        completion.TrySetResult();
        return true;
    }

    private bool HandleReleaseCapacityStreamAction(
        ulong streamId,
        ref QuicConnectionEffectAccumulator effects)
    {
        pendingPeerStreamCapacityReleaseStreamIds.Remove(streamId);
        if (TryReleasePeerStreamCapacity(streamId, ref effects))
        {
            ClearPeerStreamCapacityReleaseScheduled(streamId);
            AppendLifecycleTimerEffects(ref effects);
            return true;
        }

        if (TryDeferPeerStreamCapacityRelease(streamId))
        {
            return true;
        }

        ClearPeerStreamCapacityReleaseScheduled(streamId);
        return false;
    }

    private bool HandleReleaseCapacityStreamAction(ref QuicConnectionEffectAccumulator effects)
    {
        _ = TryDeferScheduledPeerStreamCapacityReleases();
        bool stateChanged = TryFlushPendingPeerStreamCapacityReleases(ref effects);
        if (stateChanged)
        {
            AppendLifecycleTimerEffects(ref effects);
        }

        return stateChanged;
    }

    private bool HandleFlowControlCreditUpdated(
        QuicConnectionFlowControlCreditUpdatedEvent flowControlCreditUpdatedEvent,
        ref QuicConnectionEffectAccumulator effects)
    {
        _ = TryDeferFlowControlCreditUpdate(
            flowControlCreditUpdatedEvent.MaxDataFrame,
            flowControlCreditUpdatedEvent.MaxStreamDataFrame);

        return HandleScheduledFlowControlCreditUpdated(ref effects);
    }

    private bool HandleScheduledFlowControlCreditUpdated(ref QuicConnectionEffectAccumulator effects)
    {
        _ = TryDeferScheduledFlowControlCreditUpdate();
        bool stateChanged = TryFlushPendingFlowControlCreditUpdates(ref effects);
        if (stateChanged)
        {
            AppendLifecycleTimerEffects(ref effects);
        }

        return stateChanged;
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
            exception = new InvalidOperationException(
                $"The connection is not established. Phase={phase} ActivePath={(activePath is null ? "null" : "set")}");
            return false;
        }

        if (!tlsState.OneRttSendAuthorized)
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

    private bool TryReleasePeerStreamCapacity(ulong streamId, ref QuicConnectionEffectAccumulator effects)
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

        byte[]? streamPayloadOwner = null;
        if (!TryBuildOutboundMaxStreamsPayload(
                maxStreamsFrame,
                out ReadOnlyMemory<byte> streamPayload,
                out streamPayloadOwner))
        {
            return false;
        }

        try
        {
            if (!TryProtectAndAccountApplicationPayload(
                streamPayload,
                "The connection runtime could not protect the stream capacity release packet.",
                "The connection cannot send the stream capacity release packet.",
                ref effects,
                out QuicConnectionActivePathRecord currentPath,
                out QuicConnectionPathAmplificationState updatedAmplificationState,
                out ReadOnlyMemory<byte> protectedPacket,
                out exception,
                plaintextPayloadOwner: streamPayloadOwner))
            {
                return false;
            }

            streamPayloadOwner = null;

            if (!streamRegistry.Bookkeeping.TryCommitPeerStreamCapacityRelease(streamId, maxStreamsFrame))
            {
                return false;
            }

            activePath = currentPath with
            {
                AmplificationState = updatedAmplificationState,
            };

            AppendSendDatagramEffect(ref effects,
                currentPath.Identity,
                protectedPacket);

            return true;
        }
        finally
        {
            if (streamPayloadOwner is not null)
            {
                QuicBufferPool.ReturnBytes(streamPayloadOwner);
            }
        }
    }

    private bool TryReplayPeerStreamCapacity(
        QuicStreamsBlockedFrame streamsBlockedFrame,
        ref QuicConnectionEffectAccumulator effects)
    {
        ulong currentLimit = streamsBlockedFrame.IsBidirectional
            ? streamRegistry.Bookkeeping.IncomingBidirectionalStreamLimit
            : streamRegistry.Bookkeeping.IncomingUnidirectionalStreamLimit;
        if (streamsBlockedFrame.MaximumStreams >= currentLimit)
        {
            return false;
        }

        QuicMaxStreamsFrame maxStreamsFrame = new(streamsBlockedFrame.IsBidirectional, currentLimit);
        byte[]? streamPayloadOwner = null;
        if (!TryBuildOutboundMaxStreamsPayload(
                maxStreamsFrame,
                out ReadOnlyMemory<byte> streamPayload,
                out streamPayloadOwner))
        {
            return false;
        }

        try
        {
            if (!TryProtectAndAccountApplicationPayload(
                    streamPayload,
                    "The connection runtime could not protect the stream capacity replay packet.",
                    "The connection cannot send the stream capacity replay packet.",
                    ref effects,
                    out QuicConnectionActivePathRecord currentPath,
                    out QuicConnectionPathAmplificationState updatedAmplificationState,
                    out ReadOnlyMemory<byte> protectedPacket,
                    out _,
                    plaintextPayloadOwner: streamPayloadOwner))
            {
                return false;
            }

            streamPayloadOwner = null;
            activePath = currentPath with
            {
                AmplificationState = updatedAmplificationState,
            };

            AppendSendDatagramEffect(ref effects,
                currentPath.Identity,
                protectedPacket);
            return true;
        }
        finally
        {
            if (streamPayloadOwner is not null)
            {
                QuicBufferPool.ReturnBytes(streamPayloadOwner);
            }
        }
    }

    private bool TryDeferPeerStreamCapacityRelease(ulong streamId)
    {
        if (IsDisposed
            || terminalState is not null
            || !streamRegistry.Bookkeeping.TryPeekPeerStreamCapacityRelease(streamId, out _))
        {
            return false;
        }

        pendingPeerStreamCapacityReleaseStreamIds.Add(streamId);
        return true;
    }

    private bool TryFlushPendingPeerStreamCapacityReleases(ref QuicConnectionEffectAccumulator effects)
    {
        bool measureFlushes = RuntimeWorkItemFlushMeasurementEnabled;
        int countBefore = measureFlushes ? pendingPeerStreamCapacityReleaseStreamIds.Count : 0;
        try
        {
            return TryFlushPendingPeerStreamCapacityReleasesCore(ref effects);
        }
        finally
        {
            if (measureFlushes)
            {
                runtimeWorkItemFlushedStreamCapacityReleases += Math.Max(
                    0,
                    countBefore - pendingPeerStreamCapacityReleaseStreamIds.Count);
            }
        }
    }

    private bool TryFlushPendingPeerStreamCapacityReleasesCore(ref QuicConnectionEffectAccumulator effects)
    {
        if (pendingPeerStreamCapacityReleaseStreamIds.Count == 0)
        {
            return false;
        }

        bool stateChanged = false;
        int streamIdCount = pendingPeerStreamCapacityReleaseStreamIds.Count;
        ulong[] streamIds = ArrayPool<ulong>.Shared.Rent(streamIdCount);
        int copiedStreamIdCount = 0;
        foreach (ulong streamId in pendingPeerStreamCapacityReleaseStreamIds)
        {
            streamIds[copiedStreamIdCount++] = streamId;
        }

        try
        {
            for (int index = 0; index < copiedStreamIdCount; index++)
            {
                ulong streamId = streamIds[index];
                pendingPeerStreamCapacityReleaseStreamIds.Remove(streamId);
                if (TryReleasePeerStreamCapacity(streamId, ref effects))
                {
                    ClearPeerStreamCapacityReleaseScheduled(streamId);
                    stateChanged = true;
                    continue;
                }

                if (TryDeferPeerStreamCapacityRelease(streamId))
                {
                    break;
                }

                ClearPeerStreamCapacityReleaseScheduled(streamId);
            }
        }
        finally
        {
            ArrayPool<ulong>.Shared.Return(streamIds);
        }

        return stateChanged;
    }

    private bool TrySendRetireConnectionIdFrame(
        ulong connectionId,
        ref QuicConnectionEffectAccumulator effects)
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
        ref QuicConnectionEffectAccumulator effects,
        out QuicConnectionActivePathRecord currentPath,
        out QuicConnectionPathAmplificationState updatedAmplificationState,
        out ReadOnlyMemory<byte> protectedPacket,
        out Exception? exception,
        byte[]? plaintextPayloadOwner = null)
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
            out exception,
            plaintextPayloadOwner: plaintextPayloadOwner);
    }

    private bool TryProtectAndAccountApplicationPayload(
        ReadOnlyMemory<byte> payload,
        string protectFailureMessage,
        string amplificationFailureMessage,
        bool probePacket,
        bool ackOnlyPacket,
        ulong[]? streamIds,
        bool retainPlaintextPayload,
        ref QuicConnectionEffectAccumulator effects,
        out QuicConnectionActivePathRecord currentPath,
        out QuicConnectionPathAmplificationState updatedAmplificationState,
        out ReadOnlyMemory<byte> protectedPacket,
        out Exception? exception,
        byte[]? plaintextPayloadOwner = null)
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
        QuicAckFrame? piggybackedAckFrame = null;
        int piggybackedAckFramePayloadLength = 0;
        if (!ackOnlyPacket
            && QuicConnectionAckHelpers.TryBuildApplicationAckPiggybackFrame(
                payload,
                sendRuntime.FlowController,
                nowMicros,
                out piggybackedAckFramePayloadLength,
                out QuicAckFrame includedAckFrame))
        {
            piggybackedAckFrame = includedAckFrame;
        }

        int packetPayloadLength = checked(payload.Length + piggybackedAckFramePayloadLength);
        if (!TryPreflightApplicationDataCongestionBudget(
                packetPayloadLength,
                ackOnlyPacket,
                probePacket,
                out exception))
        {
            piggybackedAckFrame?.Dispose();
            return false;
        }

        QuicBufferLease protectedPacketLease = default;
        if (!(piggybackedAckFrame is null
                ? handshakeFlowCoordinator.TryBuildProtectedApplicationDataPacketLease(
                    payload.Span,
                    tlsState.OneRttProtectPacketProtectionMaterial!.Value,
                    tlsState.CurrentOneRttKeyPhaseBit,
                    currentPath.SpinBitState.StoredValue,
                    PeerSupportsGreasedQuicBit,
                    out ulong packetNumber,
                    out protectedPacketLease)
                : handshakeFlowCoordinator.TryBuildProtectedApplicationDataPacketLease(
                    payload.Span,
                    piggybackedAckFrame,
                    piggybackedAckFramePayloadLength,
                    tlsState.OneRttProtectPacketProtectionMaterial!.Value,
                    tlsState.CurrentOneRttKeyPhaseBit,
                    currentPath.SpinBitState.StoredValue,
                    PeerSupportsGreasedQuicBit,
                    out packetNumber,
                    out protectedPacketLease)))
        {
            exception = new InvalidOperationException(protectFailureMessage);
            piggybackedAckFrame?.Dispose();
            return false;
        }

        byte[]? protectedPacketOwner = null;
        try
        {
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
                exception = CongestionControllerExhaustedException;
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

            if (ackOnlyPacket)
            {
                byte[] ackOnlyPacketBytes = protectedPacket.ToArray();
                QuicBufferPool.ReturnBytes(protectedPacketOwner);
                protectedPacketOwner = null;
                protectedPacket = ackOnlyPacketBytes;
            }

            TrackApplicationPacket(
                packetNumber,
                protectedPacket,
                ackEliciting: !ackOnlyPacket,
                ackOnlyPacket: ackOnlyPacket,
                retransmittable: !ackOnlyPacket,
                probePacket: probePacket,
                streamId: null,
                streamIds: streamIds,
                plaintextPayload: retainPlaintextPayload ? payload : default,
                plaintextPayloadOwner: plaintextPayloadOwner,
                packetBytesOwner: protectedPacketOwner);
            protectedPacketOwner = null;
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
        catch
        {
            if (protectedPacketOwner is not null)
            {
                QuicBufferPool.ReturnBytes(protectedPacketOwner);
            }

            throw;
        }
        finally
        {
            piggybackedAckFrame?.Dispose();
        }
    }

    private bool TryProtectAndAccountApplicationPayloadOnPath(
        QuicConnectionPathIdentity pathIdentity,
        ReadOnlyMemory<byte> payload,
        string protectFailureMessage,
        string amplificationFailureMessage,
        ref QuicConnectionEffectAccumulator effects,
        out QuicConnectionPathIdentity sendPathIdentity,
        out ReadOnlyMemory<byte> protectedPacket,
        out Exception? exception,
        bool retransmittable = true,
        bool probePacket = false,
        bool includeAckFrame = true,
        ulong? streamId = null,
        ulong[]? streamIds = null,
        byte[]? plaintextPayloadOwner = null,
        bool enforcePathMaximumDatagramSize = false)
    {
        sendPathIdentity = default;
        protectedPacket = ReadOnlyMemory<byte>.Empty;

        if (!tlsState.OneRttProtectPacketProtectionMaterial.HasValue)
        {
            exception = new InvalidOperationException(protectFailureMessage);
            LogApplicationSend($"app-tx protect-blocked role={tlsState.Role} reason={exception.Message}.");
            return false;
        }
        if (!TryUsePeerDestinationConnectionIdOnPath(
                pathIdentity,
                retireInactivePathConnectionIds: false,
                ref effects,
                out exception))
        {
            LogApplicationSend($"app-tx protect-blocked role={tlsState.Role} reason={exception?.Message}.");
            return false;
        }

        if (!TryPrepareOneRttProtectionForAeadLimit(protectFailureMessage, ref effects, out exception))
        {
            LogApplicationSend($"app-tx protect-blocked role={tlsState.Role} reason={exception?.Message}.");
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
            LogApplicationSend($"app-tx protect-blocked role={tlsState.Role} reason={exception.Message}.");
            return false;
        }

        ulong nowMicros = GetElapsedMicros(lastTransitionTicks);
        ReadOnlyMemory<byte> packetPayload = payload;
        QuicAckFrame? piggybackedAckFrame = null;
        int piggybackedAckFramePayloadLength = 0;
        if (includeAckFrame
            && QuicConnectionAckHelpers.TryBuildApplicationAckPiggybackFrame(
                payload,
                sendRuntime.FlowController,
                nowMicros,
                out piggybackedAckFramePayloadLength,
                out QuicAckFrame includedAckFrame))
        {
            piggybackedAckFrame = includedAckFrame;
        }

        int packetPayloadLength = checked(payload.Length + piggybackedAckFramePayloadLength);
        if (!TryPreflightApplicationDataCongestionBudget(
                packetPayloadLength,
                ackOnlyPacket: false,
                probePacket,
                out exception))
        {
            LogApplicationSend($"app-tx protect-blocked role={tlsState.Role} reason={exception?.Message} packetPayload={packetPayloadLength}.");
            piggybackedAckFrame?.Dispose();
            return false;
        }

        if (!TryGetStoredSpinBitForPath(pathIdentity, out bool pathSpinBit))
        {
            exception = new InvalidOperationException("The requested path is not available for an application packet.");
            LogApplicationSend($"app-tx protect-blocked role={tlsState.Role} reason={exception.Message}.");
            piggybackedAckFrame?.Dispose();
            return false;
        }

        QuicBufferLease protectedPacketLease = default;
        if (!(piggybackedAckFrame is null
                ? handshakeFlowCoordinator.TryBuildProtectedApplicationDataPacketLease(
                    packetPayload.Span,
                    tlsState.OneRttProtectPacketProtectionMaterial!.Value,
                    tlsState.CurrentOneRttKeyPhaseBit,
                    pathSpinBit,
                    PeerSupportsGreasedQuicBit,
                    out ulong packetNumber,
                    out protectedPacketLease)
                : handshakeFlowCoordinator.TryBuildProtectedApplicationDataPacketLease(
                    payload.Span,
                    piggybackedAckFrame,
                    piggybackedAckFramePayloadLength,
                    tlsState.OneRttProtectPacketProtectionMaterial!.Value,
                    tlsState.CurrentOneRttKeyPhaseBit,
                    pathSpinBit,
                    PeerSupportsGreasedQuicBit,
                    out packetNumber,
                    out protectedPacketLease)))
        {
            exception = new InvalidOperationException(protectFailureMessage);
            LogApplicationSend($"app-tx protect-blocked role={tlsState.Role} reason={exception.Message}.");
            piggybackedAckFrame?.Dispose();
            return false;
        }

        byte[]? protectedPacketOwner = null;
        try
        {
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
                LogApplicationSend($"app-tx protect-blocked role={tlsState.Role} reason={exception.Message}.");
                return false;
            }

            if (!sendRuntime.FlowController.CanSend(
                    QuicPacketNumberSpace.ApplicationData,
                    (ulong)protectedPacket.Length,
                    isProbePacket: probePacket))
            {
                QuicBufferPool.ReturnBytes(protectedPacketOwner);
                exception = CongestionControllerExhaustedException;
                LogApplicationSend($"app-tx protect-blocked role={tlsState.Role} reason={exception.Message} packet={protectedPacket.Length}.");
                return false;
            }

            if (enforcePathMaximumDatagramSize
                && !maximumDatagramSizeState.CanSend((ulong)protectedPacket.Length))
            {
                QuicBufferPool.ReturnBytes(protectedPacketOwner);
                exception = new InvalidOperationException("The requested path cannot send an ordinary packet.");
                LogApplicationSend($"app-tx protect-blocked role={tlsState.Role} reason={exception.Message} packet={protectedPacket.Length}.");
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
                    LogApplicationSend($"app-tx protect-blocked role={tlsState.Role} reason={exception.Message} packet={protectedPacket.Length}.");
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
                    LogApplicationSend($"app-tx protect-blocked role={tlsState.Role} reason={exception.Message} packet={protectedPacket.Length}.");
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
                LogApplicationSend($"app-tx protect-blocked role={tlsState.Role} reason={exception.Message} packet={protectedPacket.Length}.");
                return false;
            }

            TrackApplicationPacket(
                packetNumber,
                protectedPacket,
                retransmittable: retransmittable,
                probePacket: probePacket,
                streamId: streamId,
                streamIds: streamIds,
                plaintextPayload: payload,
                plaintextPayloadOwner: plaintextPayloadOwner,
                packetBytesOwner: protectedPacketOwner);
            protectedPacketOwner = null;
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
            LogApplicationSend(
                $"app-tx protect-ready role={tlsState.Role} packet={protectedPacket.Length} payload={payload.Length} path={sendPathIdentity} packetNumber={packetNumber}.");
            return true;
        }
        catch
        {
            if (protectedPacketOwner is not null)
            {
                QuicBufferPool.ReturnBytes(protectedPacketOwner);
            }

            throw;
        }
        finally
        {
            piggybackedAckFrame?.Dispose();
        }
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
            exception = CongestionControllerExhaustedException;
            return false;
        }

        ulong estimatedProtectedPacketLength = EstimateProtectedApplicationDataPacketLength(packetPayloadLength);
        if (!sendRuntime.FlowController.CanSend(
                QuicPacketNumberSpace.ApplicationData,
                estimatedProtectedPacketLength,
                isAckOnlyPacket: ackOnlyPacket,
                isProbePacket: probePacket))
        {
            exception = CongestionControllerExhaustedException;
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
        ref QuicConnectionEffectAccumulator effects,
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
        QuicConnectionEffectAccumulator accumulator = CreateEffectAccumulator(effects);
        bool stateChanged = TryFlushPendingRetransmissions(
            packetNumberSpace,
            nowTicks,
            probePacket,
            ref accumulator);
        StoreEffectAccumulator(ref effects, accumulator);
        return stateChanged;
    }

    private bool TryFlushPendingRetransmissions(
        QuicPacketNumberSpace packetNumberSpace,
        long nowTicks,
        bool probePacket,
        ref QuicConnectionEffectAccumulator effects)
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
            QuicAckFrame piggybackedAckFrame = null!;
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
                    probeRetransmission.StreamId,
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
            QuicAckFrame piggybackedAckFrame = null!;
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
                    retransmission.StreamId,
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
            bool candidateHasPreferredPayload = candidatePlan.StreamId.HasValue
                || candidatePlan.StreamIds is { Length: > 0 };
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
        // CONTEXT: Probe retransmission selection drains the queue, scores candidates, and restores the
        // non-selected plans so the scheduler can prefer crypto-progress packets without mutating the
        // underlying pending order in place. The probe-vs-non-probe and packet-number ties are deliberate.
        // SEE: code:src/Incursa.Quic/QuicConnectionRuntime.Streams.cs#TryDequeuePreferredProbeRetransmission
        // SEE: code:src/Incursa.Quic/QuicConnectionRuntime.Streams.cs#TryPromoteOutstandingProbePacket
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
        ref QuicConnectionEffectAccumulator effects)
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
        QuicConnectionEffectAccumulator accumulator = CreateEffectAccumulator(effects);
        bool stateChanged = TrySendCoalescedHandshakeAndApplicationRecoveryProbeDatagram(nowTicks, ref accumulator);
        StoreEffectAccumulator(ref effects, accumulator);
        return stateChanged;
    }

    internal bool TrySendCoalescedHandshakeAndApplicationRecoveryProbeDatagram(
        long nowTicks,
        ref QuicConnectionEffectAccumulator effects)
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
                applicationRetransmission.StreamId,
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
        piggybackedAckFrame = null!;

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
        piggybackedAckFrame = null!;

        if (initialPacketProtection is null)
        {
            return false;
        }

        if (!handshakeFlowCoordinator.TryOpenOutboundInitialPacketLease(
                retransmission.PacketBytes.Span,
                initialPacketProtection,
                out QuicBufferLease openedPacket,
                out int payloadOffset,
                out int payloadLength))
        {
            return false;
        }

        try
        {
            if (!TryParseRetransmittableCryptoFrame(
                    openedPacket.Span.Slice(payloadOffset, payloadLength),
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
                out QuicBufferLease ackFramePayload,
                out int ackFramePayloadLength,
                out piggybackedAckFrame);

            try
            {
                return handshakeFlowCoordinator.TryBuildProtectedInitialPacketForRetransmission(
                    cryptoPayload,
                    cryptoOffset,
                    longHeader.DestinationConnectionId,
                    destinationConnectionId,
                    longHeader.SourceConnectionId,
                    parsedRetryToken,
                    ackFramePayload.Span.Slice(0, ackFramePayloadLength),
                    initialPacketProtection,
                    out packetNumber,
                    out protectedPacket);
            }
            finally
            {
                ackFramePayload.Dispose();
            }
        }
        finally
        {
            openedPacket.Dispose();
        }
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
        piggybackedAckFrame = null!;

        if (!tlsState.TryGetHandshakeProtectPacketProtectionMaterial(out QuicTlsPacketProtectionMaterial handshakeMaterial))
        {
            return false;
        }

        if (!handshakeFlowCoordinator.TryOpenHandshakePacketLease(
                retransmission.PacketBytes.Span,
                handshakeMaterial,
                out QuicBufferLease openedPacket,
                out int payloadOffset,
                out int payloadLength))
        {
            return false;
        }

        try
        {
            if (!TryParseRetransmittableCryptoFrame(
                    openedPacket.Span.Slice(payloadOffset, payloadLength),
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
                out QuicBufferLease ackFramePayload,
                out int ackFramePayloadLength,
                out piggybackedAckFrame);
            try
            {
                return handshakeFlowCoordinator.TryBuildProtectedHandshakePacketForRetransmission(
                    cryptoPayload,
                    cryptoOffset,
                    longHeader.DestinationConnectionId,
                    longHeader.SourceConnectionId,
                    ackFramePayload.Span.Slice(0, ackFramePayloadLength),
                    handshakeMaterial,
                    out packetNumber,
                    out protectedPacket);
            }
            finally
            {
                ackFramePayload.Dispose();
            }
        }
        finally
        {
            openedPacket.Dispose();
        }
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

            if (QuicFrameCodec.TryConsumeAckFrame(remaining, out int ackBytesConsumed))
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
                    || !handshakeFlowCoordinator.TryOpenOutboundInitialPacketLease(
                        packetBytes.Span,
                        initialPacketProtection,
                        out QuicBufferLease openedInitialPacket,
                        out int initialPayloadOffset,
                        out int initialPayloadLength))
                {
                    return false;
                }

                try
                {
                    return TryParseCryptoProbeSelectionPriority(
                        openedInitialPacket.Span.Slice(initialPayloadOffset, initialPayloadLength),
                        out cryptoEndOffset);
                }
                finally
                {
                    openedInitialPacket.Dispose();
                }
            case QuicTlsEncryptionLevel.Handshake:
                if (!tlsState.TryGetHandshakeProtectPacketProtectionMaterial(out QuicTlsPacketProtectionMaterial handshakeMaterial)
                    || !handshakeFlowCoordinator.TryOpenHandshakePacketLease(
                        packetBytes.Span,
                        handshakeMaterial,
                        out QuicBufferLease openedHandshakePacket,
                        out int handshakePayloadOffset,
                        out int handshakePayloadLength))
                {
                    return false;
                }

                try
                {
                    return TryParseCryptoProbeSelectionPriority(
                        openedHandshakePacket.Span.Slice(handshakePayloadOffset, handshakePayloadLength),
                        out cryptoEndOffset);
                }
                finally
                {
                    openedHandshakePacket.Dispose();
                }
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

            if (QuicFrameCodec.TryConsumeAckFrame(remaining, out int ackBytesConsumed))
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
        ref QuicConnectionEffectAccumulator effects,
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
        piggybackedAckFrame = null!;

        if (!tlsState.TryGetHandshakeProtectPacketProtectionMaterial(out QuicTlsPacketProtectionMaterial handshakeMaterial))
        {
            return false;
        }

        if (!handshakeFlowCoordinator.TryOpenHandshakePacketLease(
                retransmission.PacketBytes.Span,
                handshakeMaterial,
                out QuicBufferLease openedPacket,
                out int payloadOffset,
                out int payloadLength))
        {
            return false;
        }

        try
        {
            if (!TryParseRetransmittableCryptoFrame(
                    openedPacket.Span.Slice(payloadOffset, payloadLength),
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
                out QuicBufferLease ackFramePayload,
                out int ackFramePayloadLength,
                out piggybackedAckFrame);
            try
            {
                return handshakeFlowCoordinator.TryBuildProtectedHandshakePacketForRetransmission(
                    cryptoPayload,
                    cryptoOffset,
                    destinationConnectionId,
                    longHeader.SourceConnectionId,
                    ackFramePayload.Span.Slice(0, ackFramePayloadLength),
                    handshakeMaterial,
                    out packetNumber,
                    out protectedPacket);
            }
            finally
            {
                ackFramePayload.Dispose();
            }
        }
        finally
        {
            openedPacket.Dispose();
        }
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
        ref QuicConnectionEffectAccumulator effects)
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
        ulong? streamId,
        ulong[]? streamIds,
        ReadOnlyMemory<byte> plaintextPayload)
    {
        byte[]? plaintextPayloadOwner = null;
        if (!plaintextPayload.IsEmpty)
        {
            plaintextPayloadOwner = QuicBufferPool.RentBytes(plaintextPayload.Length);
            plaintextPayload.Span.CopyTo(plaintextPayloadOwner.AsSpan(0, plaintextPayload.Length));
            plaintextPayload = plaintextPayloadOwner.AsMemory(0, plaintextPayload.Length);
        }

        try
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
                StreamId: streamId,
                StreamIds: streamIds,
                PlaintextPayload: plaintextPayload,
                OneRttKeyPhase: tlsState.CurrentOneRttKeyPhase,
                PlaintextPayloadOwner: plaintextPayloadOwner));
            plaintextPayloadOwner = null;
        }
        finally
        {
            if (plaintextPayloadOwner is not null)
            {
                QuicBufferPool.ReturnBytes(plaintextPayloadOwner);
            }
        }

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
        ref QuicConnectionEffectAccumulator effects)
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
            StreamId: retransmission.StreamId,
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
        ulong? streamId = null,
        ulong[]? streamIds = null,
        ReadOnlyMemory<byte> plaintextPayload = default,
        byte[]? plaintextPayloadOwner = null,
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
            StreamId: streamId,
            StreamIds: streamIds,
            PlaintextPayload: plaintextPayload,
            PlaintextPayloadOwner: plaintextPayloadOwner,
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
        out byte[] payload,
        out int payloadLength)
    {
        payload = [];
        payloadLength = 0;

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
        QuicBufferLease bufferLease = QuicBufferPool.RentLease(bufferLength);
        try
        {
            if (!QuicFrameCodec.TryFormatStreamFrame(
                frameType,
                streamId,
                offset,
                streamData,
                bufferLease.Span,
                out int frameBytesWritten))
            {
                return false;
            }

            if (frameBytesWritten > bufferLease.Length)
            {
                return false;
            }

            if (frameBytesWritten < bufferLease.Length)
            {
                bufferLease.Span.Slice(frameBytesWritten).Fill(0);
            }

            payload = bufferLease.TransferOwnership(out payloadLength);
            return true;
        }
        finally
        {
            bufferLease.Dispose();
        }
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
            DatagramData = datagramData,
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
        out ReadOnlyMemory<byte> payload,
        out byte[]? payloadOwner)
    {
        payload = default;
        payloadOwner = null;

        Span<byte> frameBuffer = stackalloc byte[64];
        if (!QuicFrameCodec.TryFormatMaxDataFrame(frame, frameBuffer, out int frameBytesWritten))
        {
            return false;
        }

        return TryCreatePaddedApplicationPayload(frameBuffer[..frameBytesWritten], out payload, out payloadOwner);
    }

    private bool TryBuildOutboundMaxStreamDataPayload(
        ReadOnlySpan<KeyValuePair<ulong, QuicMaxStreamDataFrame>> streamCredits,
        out ReadOnlyMemory<byte> payload,
        out byte[]? payloadOwner,
        out int payloadCreditCount)
    {
        payload = default;
        payloadOwner = null;
        payloadCreditCount = 0;
        if (streamCredits.IsEmpty)
        {
            return false;
        }

        int maximumPayloadBytes = GetMaximumFlowControlCreditPayloadBytes();
        byte[] buffer = QuicBufferPool.RentBytes(maximumPayloadBytes);
        int bytesWritten = 0;
        while (payloadCreditCount < streamCredits.Length
            && QuicFrameCodec.TryFormatMaxStreamDataFrame(
                streamCredits[payloadCreditCount].Value,
                buffer.AsSpan(bytesWritten, maximumPayloadBytes - bytesWritten),
                out int frameBytesWritten))
        {
            bytesWritten += frameBytesWritten;
            payloadCreditCount++;
        }

        if (payloadCreditCount == 0)
        {
            QuicBufferPool.ReturnBytes(buffer);
            return false;
        }

        int payloadLength = Math.Max(ApplicationMinimumProtectedPayloadLength, bytesWritten);
        buffer.AsSpan(bytesWritten, payloadLength - bytesWritten).Clear();
        payload = buffer.AsMemory(0, payloadLength);
        payloadOwner = buffer;
        return true;
    }

    private bool TryBuildOutboundFlowControlCreditPayload(
        QuicMaxDataFrame maxDataFrame,
        QuicMaxStreamDataFrame maxStreamDataFrame,
        out ReadOnlyMemory<byte> payload,
        out byte[]? payloadOwner)
    {
        payload = default;
        payloadOwner = null;

        Span<byte> frameBuffer = stackalloc byte[128];
        if (!QuicFrameCodec.TryFormatMaxDataFrame(maxDataFrame, frameBuffer, out int maxDataBytesWritten))
        {
            return false;
        }

        if (!QuicFrameCodec.TryFormatMaxStreamDataFrame(
            maxStreamDataFrame,
            frameBuffer[maxDataBytesWritten..],
            out int maxStreamDataBytesWritten))
        {
            return false;
        }

        return TryCreatePaddedApplicationPayload(
            frameBuffer[..(maxDataBytesWritten + maxStreamDataBytesWritten)],
            out payload,
            out payloadOwner);
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

    private bool TryBuildOutboundMaxStreamsPayload(
        QuicMaxStreamsFrame frame,
        out ReadOnlyMemory<byte> payload,
        out byte[]? payloadOwner)
    {
        payload = default;
        payloadOwner = null;

        Span<byte> frameBuffer = stackalloc byte[64];
        if (!QuicFrameCodec.TryFormatMaxStreamsFrame(frame, frameBuffer, out int frameBytesWritten))
        {
            return false;
        }

        return TryCreatePaddedApplicationPayload(frameBuffer[..frameBytesWritten], out payload, out payloadOwner);
    }

    private static bool TryCreatePaddedApplicationPayload(
        ReadOnlySpan<byte> frameBytes,
        out ReadOnlyMemory<byte> payload,
        out byte[]? payloadOwner)
    {
        payload = default;
        payloadOwner = null;
        if (frameBytes.IsEmpty)
        {
            return false;
        }

        int payloadLength = Math.Max(ApplicationMinimumProtectedPayloadLength, frameBytes.Length);
        payloadOwner = QuicBufferPool.RentBytes(payloadLength);
        Span<byte> payloadSpan = payloadOwner.AsSpan(0, payloadLength);
        frameBytes.CopyTo(payloadSpan);
        if (frameBytes.Length < payloadLength)
        {
            payloadSpan[frameBytes.Length..].Clear();
        }

        payload = payloadOwner.AsMemory(0, payloadLength);
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
        ref QuicConnectionEffectAccumulator effects)
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
            _ = TryDeferFlowControlCreditUpdate(maxDataFrame, default);
            _ = TryFlushPendingFlowControlCreditUpdates(ref effects);
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

    private bool TryHandleStopSendingFrame(QuicStopSendingFrame stopSendingFrame, ref QuicConnectionEffectAccumulator effects)
    {
        if (!streamRegistry.Bookkeeping.TryReceiveStopSendingFrame(
            stopSendingFrame,
            out QuicResetStreamFrame resetStreamFrame,
            out QuicTransportErrorCode errorCode))
        {
            _ = errorCode;
            return false;
        }

        NotifyStreamObservers(
            stopSendingFrame.StreamId,
            new QuicStreamNotification(
                QuicStreamNotificationKind.WriteAborted,
                CreateStreamWriteAbortedException(stopSendingFrame.ApplicationProtocolErrorCode)));

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

        TryReleasePeerStreamCapacity(stopSendingFrame.StreamId, ref effects);
        return true;
    }

    private void TryQueueInboundStreamId(ulong streamId)
    {
        if (ApplicationReceiveDebugEnabled)
        {
            Console.Error.WriteLine($"app-rx queue-inbound-stream role={tlsState.Role} stream={streamId}.");
        }

        _ = inboundStreamIds.Writer.TryWrite(streamId);
    }

    private bool TryQueueInboundDatagram(ReadOnlyMemory<byte> datagram, out ReadOnlyMemory<byte> queuedDatagram)
    {
        queuedDatagram = ReadOnlyMemory<byte>.Empty;
        if (inboundDatagrams is null)
        {
            return false;
        }

        byte[] ownedDatagram = datagram.ToArray();
        if (!inboundDatagrams.Writer.TryWrite(ownedDatagram))
        {
            return false;
        }

        queuedDatagram = ownedDatagram;
        return true;
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

        inboundStreamIds.Writer.TryComplete();
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

        inboundDatagrams.Writer.TryComplete();
    }

    private void CompletePendingStreamOpenRequests(Exception completionException)
    {
        if (pendingStreamOpenRequests.IsEmpty)
        {
            return;
        }

        foreach (KeyValuePair<long, QuicConnectionRuntime.StreamOpenRequestCompletionSource> entry in pendingStreamOpenRequests.ToArray())
        {
            if (TryRemovePendingStreamOpenRequest(entry.Key, out QuicConnectionRuntime.StreamOpenRequestCompletionSource? completion))
            {
                completion!.TrySetException(completionException);
            }
        }
    }

    private bool TryRemovePendingStreamOpenRequest(long requestId, out QuicConnectionRuntime.StreamOpenRequestCompletionSource? completion)
    {
        return pendingStreamOpenRequests.TryRemove(requestId, out completion);
    }

    private void CompletePendingStreamActionRequests(Exception completionException)
    {
        KeyValuePair<long, QuicConnectionRuntime.StreamActionRequestCompletionSource>[]? pendingRequests = null;
        int pendingRequestCount = 0;
        lock (pendingStreamActionRequestsGate)
        {
            if (pendingStreamActionRequests.Count == 0)
            {
                return;
            }

            pendingRequestCount = pendingStreamActionRequests.Count;
            pendingRequests = ArrayPool<KeyValuePair<long, QuicConnectionRuntime.StreamActionRequestCompletionSource>>.Shared.Rent(pendingRequestCount);
            int index = 0;
            foreach (KeyValuePair<long, QuicConnectionRuntime.StreamActionRequestCompletionSource> entry in pendingStreamActionRequests)
            {
                pendingRequests[index++] = entry;
            }

            pendingStreamActionRequests.Clear();
        }

        try
        {
            for (int index = 0; index < pendingRequestCount; index++)
            {
                pendingRequests[index].Value.TrySetTerminalException(completionException);
            }
        }
        finally
        {
            ArrayPool<KeyValuePair<long, QuicConnectionRuntime.StreamActionRequestCompletionSource>>.Shared.Return(
                pendingRequests!,
                clearArray: true);
        }
    }

    private void CompletePendingDatagramSendRequests(Exception completionException)
    {
        if (pendingDatagramSendRequests.IsEmpty)
        {
            return;
        }

        foreach (KeyValuePair<long, QuicConnectionRuntime.DatagramSendRequestCompletionSource> entry in pendingDatagramSendRequests.ToArray())
        {
            if (pendingDatagramSendRequests.TryRemove(entry.Key, out QuicConnectionRuntime.DatagramSendRequestCompletionSource? completion))
            {
                completion.TrySetException(completionException);
            }
        }
    }

    private void NotifyStreamObservers(ulong streamId, QuicStreamNotification notification)
    {
        streamObservers.Notify(streamId, notification);
    }

    private void NotifyAllStreamObservers(Exception completionException)
    {
        if (streamObservers.IsEmpty)
        {
            return;
        }

        streamObservers.NotifyAll(new QuicStreamNotification(
            QuicStreamNotificationKind.ConnectionTerminated,
            completionException));
    }
}
