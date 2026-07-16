// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Diagnostics.CodeAnalysis;

namespace Incursa.Quic;

internal sealed class QuicConnectionStreamState
{
    private const int StreamReceiveCoalescingThreshold = 1024;
    private const int InitialStreamReceiveBlockSize = 4 * 1024;
    private const int ContinuationStreamReceiveBlockSize = 8 * 1024;
    private const ulong MaximumFlowControlLimit = QuicVariableLengthInteger.MaxValue;
    private const ulong MaximumStreamCount = 1UL << 60;
    private const ulong UnidirectionalBit = 0x02;
    private const int StreamIdTypeBitCount = 2;
    private const int MaximumInitialTrackedStreamCapacity = 128;
    private const int InlineBufferedSegmentCapacity = 2;
    private const int SpilledBufferedSegmentInitialCapacity = InlineBufferedSegmentCapacity * 4;
    private const int MaximumCachedBufferedSegmentCapacity = 64;

    [ThreadStatic]
    private static List<BufferedSegment>? cachedBufferedSegmentList;

    [ThreadStatic]
    private static List<BufferedSegment>? secondaryCachedBufferedSegmentList;

    private readonly bool isServer;
    private readonly object syncRoot = new();
    private readonly Dictionary<ulong, StreamState> streams;

    private ulong initialLocalBidirectionalReceiveLimit;
    private ulong initialPeerBidirectionalReceiveLimit;
    private ulong initialPeerUnidirectionalReceiveLimit;
    private ulong localBidirectionalSendLimit;
    private ulong localUnidirectionalSendLimit;
    private ulong peerBidirectionalSendLimit;

    private ulong nextLocalBidirectionalStreamIndex;
    private ulong nextLocalUnidirectionalStreamIndex;
    private ulong incomingBidirectionalStreamLimit;
    private ulong incomingUnidirectionalStreamLimit;
    private ulong peerBidirectionalStreamLimit;
    private ulong peerUnidirectionalStreamLimit;
    private ulong connectionAccountedBytesReceived;
    private ulong connectionUniqueBytesSent;
    private ulong highestCreatedIncomingBidirectionalStreamIndex;
    private ulong highestCreatedIncomingUnidirectionalStreamIndex;
    private long retainedReceiveBufferCount;
    private long retainedReceiveBufferBytes;
    private long bufferedReadableBytes;
    private long bufferedReadableStreamCount;
    private bool hasCreatedIncomingBidirectionalStream;
    private bool hasCreatedIncomingUnidirectionalStream;

    public QuicConnectionStreamState(QuicConnectionStreamStateOptions options)
    {
        ValidateLimits(options);

        streams = new Dictionary<ulong, StreamState>(GetInitialTrackedStreamCapacity(options));
        isServer = options.IsServer;
        ConnectionReceiveLimit = options.InitialConnectionReceiveLimit;
        ConnectionSendLimit = options.InitialConnectionSendLimit;
        incomingBidirectionalStreamLimit = options.InitialIncomingBidirectionalStreamLimit;
        incomingUnidirectionalStreamLimit = options.InitialIncomingUnidirectionalStreamLimit;
        peerBidirectionalStreamLimit = options.InitialPeerBidirectionalStreamLimit;
        peerUnidirectionalStreamLimit = options.InitialPeerUnidirectionalStreamLimit;

        initialLocalBidirectionalReceiveLimit = options.InitialLocalBidirectionalReceiveLimit;
        initialPeerBidirectionalReceiveLimit = options.InitialPeerBidirectionalReceiveLimit;
        initialPeerUnidirectionalReceiveLimit = options.InitialPeerUnidirectionalReceiveLimit;
        localBidirectionalSendLimit = options.InitialLocalBidirectionalSendLimit;
        localUnidirectionalSendLimit = options.InitialLocalUnidirectionalSendLimit;
        peerBidirectionalSendLimit = options.InitialPeerBidirectionalSendLimit;
    }

    public bool IsServer => isServer;
    public ulong ConnectionReceiveLimit { get; private set; }
    public ulong ConnectionSendLimit { get; private set; }
    public ulong ConnectionAccountedBytesReceived => connectionAccountedBytesReceived;
    public ulong ConnectionUniqueBytesSent => connectionUniqueBytesSent;
    public ulong PeerBidirectionalStreamLimit => peerBidirectionalStreamLimit;
    public ulong PeerUnidirectionalStreamLimit => peerUnidirectionalStreamLimit;
    public ulong IncomingBidirectionalStreamLimit => incomingBidirectionalStreamLimit;
    public ulong IncomingUnidirectionalStreamLimit => incomingUnidirectionalStreamLimit;

    // CONTEXT: Local stream reservation stays split from commit so callers can check whether the next
    // stream ID is available and surface STREAMS_BLOCKED without consuming quota until a stream is
    // actually opened.
    // SEE: code:src/Incursa.Quic/QuicConnectionStreamState.cs#TryOpenLocalStream
    // SEE: code:src/Incursa.Quic/QuicConnectionStreamState.cs#TryPeekLocalStream
    public bool TryPeekLocalStream(bool bidirectional, out QuicStreamId streamId, out QuicStreamsBlockedFrame blockedFrame)
    {
        lock (syncRoot)
        {
            ulong nextIndex = bidirectional ? nextLocalBidirectionalStreamIndex : nextLocalUnidirectionalStreamIndex;
            ulong limit = bidirectional ? peerBidirectionalStreamLimit : peerUnidirectionalStreamLimit;

            if (nextIndex >= limit)
            {
                streamId = default;
                blockedFrame = new QuicStreamsBlockedFrame(bidirectional, limit);
                return false;
            }

            streamId = new QuicStreamId(BuildLocalStreamIdValue(bidirectional, nextIndex));
            blockedFrame = default;
            return true;
        }
    }

    public bool TryOpenLocalStream(bool bidirectional, out QuicStreamId streamId, out QuicStreamsBlockedFrame blockedFrame)
    {
        lock (syncRoot)
        {
            if (!TryPeekLocalStream(bidirectional, out streamId, out blockedFrame))
            {
                return false;
            }

            streams.Add(streamId.Value, CreateLocalStreamState(streamId));

            if (bidirectional)
            {
                nextLocalBidirectionalStreamIndex++;
            }
            else
            {
                nextLocalUnidirectionalStreamIndex++;
            }

            return true;
        }
    }

    public bool TryApplyMaxDataFrame(QuicMaxDataFrame frame)
    {
        lock (syncRoot)
        {
            if (frame.MaximumData <= ConnectionSendLimit)
            {
                return false;
            }

            ConnectionSendLimit = frame.MaximumData;
            return true;
        }
    }

    public bool TryApplyPeerInitialMaxData(ulong initialMaxData)
    {
        lock (syncRoot)
        {
            ValidateFlowControlLimit(initialMaxData);
            if (ConnectionSendLimit == initialMaxData)
            {
                return false;
            }

            ConnectionSendLimit = initialMaxData;
            return true;
        }
    }

    public bool TryApplyMaxStreamsFrame(QuicMaxStreamsFrame frame)
    {
        lock (syncRoot)
        {
            if (frame.IsBidirectional)
            {
                if (frame.MaximumStreams <= peerBidirectionalStreamLimit)
                {
                    return false;
                }

                peerBidirectionalStreamLimit = frame.MaximumStreams;
                EnsureTrackedStreamCapacity();
                return true;
            }

            if (frame.MaximumStreams <= peerUnidirectionalStreamLimit)
            {
                return false;
            }

            peerUnidirectionalStreamLimit = frame.MaximumStreams;
            EnsureTrackedStreamCapacity();
            return true;
        }
    }

    // CONTEXT: Peer-initiated capacity is released only after the stream is fully closed so the
    // connection does not advertise extra incoming credit while data or reset state is still pending.
    // The peek/commit split lets callers decide whether to emit MAX_STREAMS without incrementing the
    // limit twice for the same stream.
    // SEE: code:src/Incursa.Quic/QuicConnectionStreamState.cs#TryPeekPeerStreamCapacityRelease
    // SEE: code:src/Incursa.Quic/QuicConnectionStreamState.cs#TryCommitPeerStreamCapacityRelease
    public bool TryPeekPeerStreamCapacityRelease(ulong streamIdValue, out QuicMaxStreamsFrame frame)
    {
        lock (syncRoot)
        {
            frame = default;

            QuicStreamId streamId = new(streamIdValue);
            if (!IsPeerInitiated(streamId)
                || !streams.TryGetValue(streamIdValue, out StreamState? state)
                || state.PeerCapacityReleaseReported
                || !IsPeerStreamFullyClosed(state))
            {
                return false;
            }

            ulong currentLimit = streamId.IsBidirectional
                ? incomingBidirectionalStreamLimit
                : incomingUnidirectionalStreamLimit;
            if (currentLimit == MaximumStreamCount)
            {
                return false;
            }

            frame = new QuicMaxStreamsFrame(streamId.IsBidirectional, currentLimit + 1);
            return true;
        }
    }

    public bool TryCommitPeerStreamCapacityRelease(ulong streamIdValue, QuicMaxStreamsFrame frame)
    {
        lock (syncRoot)
        {
            QuicStreamId streamId = new(streamIdValue);
            if (!IsPeerInitiated(streamId)
                || frame.IsBidirectional != streamId.IsBidirectional
                || !streams.TryGetValue(streamIdValue, out StreamState? state)
                || state.PeerCapacityReleaseReported
                || !IsPeerStreamFullyClosed(state))
            {
                return false;
            }

            if (streamId.IsBidirectional)
            {
                if (frame.MaximumStreams <= incomingBidirectionalStreamLimit)
                {
                    return false;
                }

                incomingBidirectionalStreamLimit = frame.MaximumStreams;
            }
            else
            {
                if (frame.MaximumStreams <= incomingUnidirectionalStreamLimit)
                {
                    return false;
                }

                incomingUnidirectionalStreamLimit = frame.MaximumStreams;
            }

            state.PeerCapacityReleaseReported = true;
            return true;
        }
    }

    public bool TryApplyMaxStreamDataFrame(QuicMaxStreamDataFrame frame, out QuicTransportErrorCode errorCode)
    {
        lock (syncRoot)
        {
            errorCode = default;

            QuicStreamId streamId = new(frame.StreamId);
            if (!TryResolveSendCapableStream(streamId, allowImplicitPeerOpen: true, out StreamState? state, out errorCode))
            {
                return false;
            }

            if (frame.MaximumStreamData <= state.SendLimit)
            {
                return false;
            }

            state.SendLimit = frame.MaximumStreamData;
            return true;
        }
    }

    public bool TryMarkPeerAcceptQueued(ulong streamIdValue)
    {
        lock (syncRoot)
        {
            if (!streams.TryGetValue(streamIdValue, out StreamState? state)
                || !IsPeerInitiated(new QuicStreamId(streamIdValue))
                || !state.HasReceivePart
                || state.PeerAcceptQueued)
            {
                return false;
            }

            state.PeerAcceptQueued = true;
            return true;
        }
    }

    public bool TryApplyPeerTransportParameterSendLimits(
        ulong localBidirectionalLimit,
        ulong peerBidirectionalLimit,
        ulong localUnidirectionalLimit)
    {
        lock (syncRoot)
        {
            ValidateFlowControlLimit(localBidirectionalLimit);
            ValidateFlowControlLimit(peerBidirectionalLimit);
            ValidateFlowControlLimit(localUnidirectionalLimit);

            bool stateChanged = false;

            if (localBidirectionalSendLimit != localBidirectionalLimit)
            {
                localBidirectionalSendLimit = localBidirectionalLimit;
                stateChanged = true;
            }

            if (peerBidirectionalSendLimit != peerBidirectionalLimit)
            {
                peerBidirectionalSendLimit = peerBidirectionalLimit;
                stateChanged = true;
            }

            if (localUnidirectionalSendLimit != localUnidirectionalLimit)
            {
                localUnidirectionalSendLimit = localUnidirectionalLimit;
                stateChanged = true;
            }

            foreach (KeyValuePair<ulong, StreamState> entry in streams)
            {
                QuicStreamId streamId = new(entry.Key);
                if (!entry.Value.HasSendPart)
                {
                    continue;
                }

                ulong updatedSendLimit = ResolveCurrentSendLimit(streamId);
                if (entry.Value.SendLimit == updatedSendLimit)
                {
                    continue;
                }

                entry.Value.SendLimit = updatedSendLimit;
                stateChanged = true;
            }

            return stateChanged;
        }
    }

    public bool TryApplyInitialReceiveLimits(
        ulong connectionReceiveLimit,
        ulong localBidirectionalReceiveLimit,
        ulong peerBidirectionalReceiveLimit,
        ulong peerUnidirectionalReceiveLimit)
    {
        lock (syncRoot)
        {
            ValidateFlowControlLimit(connectionReceiveLimit);
            ValidateFlowControlLimit(localBidirectionalReceiveLimit);
            ValidateFlowControlLimit(peerBidirectionalReceiveLimit);
            ValidateFlowControlLimit(peerUnidirectionalReceiveLimit);

            bool stateChanged = false;

            if (ConnectionReceiveLimit != connectionReceiveLimit)
            {
                ConnectionReceiveLimit = connectionReceiveLimit;
                stateChanged = true;
            }

            if (initialLocalBidirectionalReceiveLimit != localBidirectionalReceiveLimit)
            {
                initialLocalBidirectionalReceiveLimit = localBidirectionalReceiveLimit;
                stateChanged = true;
            }

            if (initialPeerBidirectionalReceiveLimit != peerBidirectionalReceiveLimit)
            {
                initialPeerBidirectionalReceiveLimit = peerBidirectionalReceiveLimit;
                stateChanged = true;
            }

            if (initialPeerUnidirectionalReceiveLimit != peerUnidirectionalReceiveLimit)
            {
                initialPeerUnidirectionalReceiveLimit = peerUnidirectionalReceiveLimit;
                stateChanged = true;
            }

            foreach (KeyValuePair<ulong, StreamState> entry in streams)
            {
                if (!entry.Value.HasReceivePart)
                {
                    continue;
                }

                QuicStreamId streamId = new(entry.Key);
                ulong updatedReceiveLimit = ResolveCurrentReceiveLimit(streamId);
                if (entry.Value.ReceiveLimit == updatedReceiveLimit)
                {
                    continue;
                }

                entry.Value.ReceiveLimit = updatedReceiveLimit;
                stateChanged = true;
            }

            return stateChanged;
        }
    }

    public bool TryApplyInitialIncomingStreamLimits(
        ulong bidirectionalStreamLimit,
        ulong unidirectionalStreamLimit)
    {
        lock (syncRoot)
        {
            ValidateStreamCount(bidirectionalStreamLimit);
            ValidateStreamCount(unidirectionalStreamLimit);
            if (hasCreatedIncomingBidirectionalStream || hasCreatedIncomingUnidirectionalStream)
            {
                throw new InvalidOperationException("Initial incoming stream limits cannot change after a peer stream is created.");
            }

            if (incomingBidirectionalStreamLimit == bidirectionalStreamLimit
                && incomingUnidirectionalStreamLimit == unidirectionalStreamLimit)
            {
                return false;
            }

            incomingBidirectionalStreamLimit = bidirectionalStreamLimit;
            incomingUnidirectionalStreamLimit = unidirectionalStreamLimit;
            EnsureTrackedStreamCapacity();
            return true;
        }
    }

    public bool TryReserveSendCapacity(
        ulong streamIdValue,
        ulong offset,
        int length,
        bool fin,
        out QuicDataBlockedFrame dataBlockedFrame,
        out QuicStreamDataBlockedFrame streamDataBlockedFrame,
        out QuicTransportErrorCode errorCode)
    {
        lock (syncRoot)
        {
            QuicStreamId streamId = new(streamIdValue);
            if (!TryResolveSendCapableStream(streamId, allowImplicitPeerOpen: false, out StreamState? state, out errorCode))
            {
                dataBlockedFrame = default;
                streamDataBlockedFrame = default;
                return false;
            }

            return TryReserveSendCapacityCore(
                state,
                streamIdValue,
                offset,
                length,
                fin,
                out dataBlockedFrame,
                out streamDataBlockedFrame,
                out errorCode);
        }
    }

    internal QuicConnectionStreamWritePreparationStatus PrepareStreamWrite(
        ulong streamIdValue,
        int length,
        bool fin,
        out QuicConnectionStreamWritePreparation preparation,
        out QuicDataBlockedFrame dataBlockedFrame,
        out QuicStreamDataBlockedFrame streamDataBlockedFrame,
        out QuicTransportErrorCode errorCode)
    {
        lock (syncRoot)
        {
            preparation = default;
            dataBlockedFrame = default;
            streamDataBlockedFrame = default;
            errorCode = default;

            QuicStreamId streamId = new(streamIdValue);
            if (!streams.TryGetValue(streamIdValue, out StreamState? state))
            {
                if (!IsLocalInitiated(streamId))
                {
                    return QuicConnectionStreamWritePreparationStatus.Unavailable;
                }

                if (!TryPeekLocalStream(streamId.IsBidirectional, out QuicStreamId nextStreamId, out _))
                {
                    errorCode = QuicTransportErrorCode.StreamLimitError;
                    return QuicConnectionStreamWritePreparationStatus.Unavailable;
                }

                if (nextStreamId.Value != streamIdValue)
                {
                    return QuicConnectionStreamWritePreparationStatus.Unavailable;
                }

                if (!TryOpenLocalStream(streamId.IsBidirectional, out QuicStreamId committedStreamId, out _)
                    || committedStreamId.Value != streamIdValue
                    || !streams.TryGetValue(streamIdValue, out state))
                {
                    errorCode = QuicTransportErrorCode.StreamStateError;
                    return QuicConnectionStreamWritePreparationStatus.Unavailable;
                }
            }

            if (!state.HasSendPart || state.SendState == QuicStreamSendState.None)
            {
                return QuicConnectionStreamWritePreparationStatus.NotWritable;
            }

            if (state.SendState is QuicStreamSendState.DataSent
                or QuicStreamSendState.DataRecvd
                or QuicStreamSendState.ResetSent
                or QuicStreamSendState.ResetRecvd)
            {
                return QuicConnectionStreamWritePreparationStatus.Completed;
            }

            QuicConnectionStreamSendStateSnapshot sendStateBeforeWrite = CaptureSendState(streamIdValue, state);
            ulong writeOffset = state.SentRanges.TotalLength;
            if (!TryReserveSendCapacityCore(
                    state,
                    streamIdValue,
                    writeOffset,
                    length,
                    fin,
                    out dataBlockedFrame,
                    out streamDataBlockedFrame,
                    out errorCode))
            {
                return errorCode != default
                    ? QuicConnectionStreamWritePreparationStatus.Error
                    : QuicConnectionStreamWritePreparationStatus.Blocked;
            }

            preparation = new QuicConnectionStreamWritePreparation(
                writeOffset,
                sendStateBeforeWrite);
            return QuicConnectionStreamWritePreparationStatus.Reserved;
        }
    }

    private bool TryReserveSendCapacityCore(
        StreamState state,
        ulong streamIdValue,
        ulong offset,
        int length,
        bool fin,
        out QuicDataBlockedFrame dataBlockedFrame,
        out QuicStreamDataBlockedFrame streamDataBlockedFrame,
        out QuicTransportErrorCode errorCode)
    {
        dataBlockedFrame = default;
        streamDataBlockedFrame = default;
        errorCode = default;

        if (length < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(length));
        }

        if (offset > MaximumFlowControlLimit - (ulong)length)
        {
            errorCode = QuicTransportErrorCode.FinalSizeError;
            return false;
        }

        if (IsStreamSendClosedForNewFrames(state.SendState))
        {
            errorCode = QuicTransportErrorCode.StreamStateError;
            return false;
        }

        ulong endExclusive = offset + (ulong)length;
        if (state.SendFinalSize.HasValue)
        {
            if ((fin && endExclusive != state.SendFinalSize.Value)
                || endExclusive > state.SendFinalSize.Value
                || (length > 0 && offset >= state.SendFinalSize.Value))
            {
                errorCode = QuicTransportErrorCode.FinalSizeError;
                return false;
            }
        }
        else if (fin && endExclusive < state.HighestSentOffset)
        {
            errorCode = QuicTransportErrorCode.FinalSizeError;
            return false;
        }

        if (state.SendState == QuicStreamSendState.Ready)
        {
            state.SendState = QuicStreamSendState.Send;
        }

        if (state.SendState != QuicStreamSendState.DataSent
            && endExclusive > state.SendLimit)
        {
            streamDataBlockedFrame = new QuicStreamDataBlockedFrame(streamIdValue, state.SendLimit);
            return false;
        }

        ulong additionalBytes = state.SentRanges.MeasureAdditionalCoverage(offset, endExclusive);
        ulong remainingConnectionSendCapacity = ConnectionSendLimit > connectionUniqueBytesSent
            ? ConnectionSendLimit - connectionUniqueBytesSent
            : 0;
        if (additionalBytes > 0 && additionalBytes > remainingConnectionSendCapacity)
        {
            dataBlockedFrame = new QuicDataBlockedFrame(ConnectionSendLimit);
            return false;
        }

        if (additionalBytes > 0)
        {
            state.SentRanges.Add(offset, endExclusive);
            connectionUniqueBytesSent += additionalBytes;
        }

        if (fin && !state.SendFinalSize.HasValue)
        {
            state.SendFinalSize = endExclusive;
        }

        if (fin)
        {
            state.SendState = QuicStreamSendState.DataSent;
        }

        state.HighestSentOffset = Math.Max(state.HighestSentOffset, endExclusive);
        return true;
    }

    public bool TryReceiveStreamFrame(QuicStreamFrame frame, out QuicTransportErrorCode errorCode, QuicApplicationDataEpoch epoch = QuicApplicationDataEpoch.OneRtt)
    {
        lock (syncRoot)
        {
            errorCode = default;
            if (!TryResolveReceiveCapableStream(frame.StreamId, out StreamState? state, out errorCode))
            {
                return false;
            }

            ulong endExclusive = frame.Offset + (ulong)frame.StreamDataLength;
            if (state.ReceiveState is QuicStreamReceiveState.ResetRecvd or QuicStreamReceiveState.ResetRead)
            {
                if (ViolatesKnownReceiveFinalSize(state, frame.Offset, endExclusive, frame.StreamDataLength, frame.IsFin))
                {
                    errorCode = QuicTransportErrorCode.FinalSizeError;
                    return false;
                }

                return true;
            }

            if (ViolatesKnownReceiveFinalSize(state, frame.Offset, endExclusive, frame.StreamDataLength, frame.IsFin))
            {
                errorCode = QuicTransportErrorCode.FinalSizeError;
                return false;
            }

            ulong? proposedFinalSize = frame.IsFin ? endExclusive : state.ReceiveFinalSize;
            if (frame.IsFin && !state.ReceiveFinalSize.HasValue && endExclusive < state.HighestReceivedOffset)
            {
                errorCode = QuicTransportErrorCode.FinalSizeError;
                return false;
            }

            if (proposedFinalSize.HasValue && proposedFinalSize.Value > state.ReceiveLimit)
            {
                errorCode = QuicTransportErrorCode.FlowControlError;
                return false;
            }

            if (endExclusive > state.ReceiveLimit)
            {
                errorCode = QuicTransportErrorCode.FlowControlError;
                return false;
            }

            if (state.ReceiveState is QuicStreamReceiveState.DataRecvd or QuicStreamReceiveState.DataRead)
            {
                return true;
            }

            ulong additionalBytes = state.ReceivedRanges.MeasureAdditionalCoverage(frame.Offset, endExclusive);
            ulong newUniqueBytes = state.ReceivedRanges.TotalLength + additionalBytes;
            ulong newAccountedBytes = proposedFinalSize.HasValue ? Math.Max(newUniqueBytes, proposedFinalSize.Value) : newUniqueBytes;
            ulong additionalAccountedBytes = newAccountedBytes - state.AccountedBytes;

            if (additionalAccountedBytes > ConnectionReceiveLimit - connectionAccountedBytesReceived)
            {
                errorCode = QuicTransportErrorCode.FlowControlError;
                return false;
            }

            state.ReceivedRanges.Add(frame.Offset, endExclusive);
            state.HighestReceivedOffset = Math.Max(state.HighestReceivedOffset, endExclusive);
            state.AccountedBytes = newAccountedBytes;
            connectionAccountedBytesReceived += additionalAccountedBytes;

            if (proposedFinalSize.HasValue)
            {
                state.ReceiveFinalSize = proposedFinalSize.Value;
            }

            if (frame.StreamDataLength > 0 && additionalBytes > 0)
            {
                InsertReadableBytes(state, frame.Offset, frame.StreamData);
            }

            if (additionalBytes > 0)
            {
                if (epoch == QuicApplicationDataEpoch.ZeroRtt)
                {
                    state.ReceivedZeroRttData = true;
                }
                else
                {
                    state.ReceivedOneRttData = true;
                }
            }

            UpdateReceiveState(state);
            return true;
        }
    }

    public bool TryReceiveStreamDataBlockedFrame(
        QuicStreamDataBlockedFrame frame,
        out QuicTransportErrorCode errorCode)
    {
        lock (syncRoot)
        {
            QuicStreamId streamId = new(frame.StreamId);
            return TryResolveReceiveCapableStream(streamId, out _, out errorCode);
        }
    }

    public bool TryReceiveResetStreamFrame(
        QuicResetStreamFrame frame,
        out QuicMaxDataFrame maxDataFrame,
        out QuicTransportErrorCode errorCode)
    {
        lock (syncRoot)
        {
            return TryReceiveResetStreamFrame(frame, out maxDataFrame, out errorCode, suppressResetSignalWhenDataRecvd: false);
        }
    }

    internal bool TryReceiveResetStreamFrame(
        QuicResetStreamFrame frame,
        out QuicMaxDataFrame maxDataFrame,
        out QuicTransportErrorCode errorCode,
        bool suppressResetSignalWhenDataRecvd)
    {
        lock (syncRoot)
        {
            maxDataFrame = default;
            errorCode = default;

            QuicStreamId streamId = new(frame.StreamId);
            if (!TryResolveReceiveCapableStream(streamId, out StreamState? state, out errorCode))
            {
                return false;
            }

            if (state.ReceiveFinalSize.HasValue && state.ReceiveFinalSize.Value != frame.FinalSize)
            {
                errorCode = QuicTransportErrorCode.FinalSizeError;
                return false;
            }

            if (frame.FinalSize < state.HighestReceivedOffset)
            {
                errorCode = QuicTransportErrorCode.FinalSizeError;
                return false;
            }

            if (frame.FinalSize > state.ReceiveLimit)
            {
                errorCode = QuicTransportErrorCode.FlowControlError;
                return false;
            }

            ulong newAccountedBytes = Math.Max(state.AccountedBytes, frame.FinalSize);
            ulong additionalAccountedBytes = newAccountedBytes - state.AccountedBytes;
            if (additionalAccountedBytes > ConnectionReceiveLimit - connectionAccountedBytesReceived)
            {
                errorCode = QuicTransportErrorCode.FlowControlError;
                return false;
            }

            if (suppressResetSignalWhenDataRecvd && state.ReceiveState == QuicStreamReceiveState.DataRecvd)
            {
                return true;
            }

            if (state.BufferedReadableBytes > 0)
            {
                ulong increasedLimit = IncreaseLimit(ConnectionReceiveLimit, (ulong)state.BufferedReadableBytes);
                if (increasedLimit != ConnectionReceiveLimit)
                {
                    ConnectionReceiveLimit = increasedLimit;
                    maxDataFrame = new QuicMaxDataFrame(ConnectionReceiveLimit);
                }
            }

            ReleaseBufferedSegments(state);
            DecreaseBufferedReadableBytes(state, state.BufferedReadableBytes);
            state.ReceiveFinalSize = frame.FinalSize;
            state.HighestReceivedOffset = Math.Max(state.HighestReceivedOffset, frame.FinalSize);
            state.AccountedBytes = newAccountedBytes;
            connectionAccountedBytesReceived += additionalAccountedBytes;
            state.ReceiveState = QuicStreamReceiveState.ResetRecvd;
            if (!state.LocalStopSendingFrameSent)
            {
                state.ReceiveAbortErrorCode = frame.ApplicationProtocolErrorCode;
                state.HasReceiveAbortErrorCode = true;
            }

            return true;
        }
    }

    public bool TryAbortLocalStreamWrites(
        ulong streamIdValue,
        out ulong finalSize,
        out QuicTransportErrorCode errorCode)
    {
        lock (syncRoot)
        {
            finalSize = 0;
            errorCode = default;

            QuicStreamId streamId = new(streamIdValue);
            if (!TryResolveOrOpenLocalSendCapableStream(streamId, out StreamState? state, out errorCode))
            {
                return false;
            }

            if (IsStreamSendClosedForNewFrames(state.SendState))
            {
                errorCode = QuicTransportErrorCode.StreamStateError;
                return false;
            }

            finalSize = state.SendFinalSize ?? state.HighestSentOffset;
            state.SendFinalSize = finalSize;
            state.SendState = QuicStreamSendState.ResetSent;
            return true;
        }
    }

    public bool TryReceiveStopSendingFrame(
        QuicStopSendingFrame frame,
        out QuicResetStreamFrame resetStreamFrame,
        out QuicTransportErrorCode errorCode)
    {
        lock (syncRoot)
        {
            resetStreamFrame = default;
            errorCode = default;

            QuicStreamId streamId = new(frame.StreamId);
            if (!TryResolveSendCapableStream(streamId, allowImplicitPeerOpen: true, out StreamState? state, out errorCode))
            {
                return false;
            }

            if (state.SendState is QuicStreamSendState.DataRecvd
                or QuicStreamSendState.ResetSent
                or QuicStreamSendState.ResetRecvd)
            {
                errorCode = QuicTransportErrorCode.StreamStateError;
                return false;
            }

            if (state.HasReceivePart
                && state.ReceiveState is QuicStreamReceiveState.ResetRecvd or QuicStreamReceiveState.ResetRead)
            {
                errorCode = QuicTransportErrorCode.StreamStateError;
                return false;
            }

            ulong finalSize = state.SendFinalSize ?? state.HighestSentOffset;
            state.SendFinalSize = finalSize;
            state.SendState = QuicStreamSendState.ResetSent;
            state.SendAbortErrorCode = frame.ApplicationProtocolErrorCode;
            state.HasSendAbortErrorCode = true;
            resetStreamFrame = new QuicResetStreamFrame(frame.StreamId, frame.ApplicationProtocolErrorCode, finalSize);
            return true;
        }
    }

    public bool TryMarkLocalStopSendingFrameSent(
        ulong streamIdValue,
        out QuicTransportErrorCode errorCode)
    {
        lock (syncRoot)
        {
            errorCode = default;
            if (!streams.TryGetValue(streamIdValue, out StreamState? state) || !state.HasReceivePart)
            {
                errorCode = QuicTransportErrorCode.StreamStateError;
                return false;
            }

            state.LocalStopSendingFrameSent = true;
            return true;
        }
    }

    public bool TryReadStreamData(
        ulong streamIdValue,
        Span<byte> destination,
        out int bytesWritten,
        out bool completed,
        out QuicMaxDataFrame maxDataFrame,
        out QuicMaxStreamDataFrame maxStreamDataFrame,
        out QuicTransportErrorCode errorCode)
    {
        lock (syncRoot)
        {
            bytesWritten = 0;
            completed = false;
            maxDataFrame = default;
            maxStreamDataFrame = default;
            errorCode = default;

            if (!streams.TryGetValue(streamIdValue, out StreamState? state) || !state.HasReceivePart)
            {
                return false;
            }

            if (state.ReceiveState is QuicStreamReceiveState.ResetRecvd or QuicStreamReceiveState.ResetRead)
            {
                return false;
            }

            if (destination.IsEmpty || GetBufferedSegmentCount(state) == 0)
            {
                completed = state.ReceiveFinalSize.HasValue && state.ReadOffset == state.ReceiveFinalSize.Value;
                return false;
            }

            ulong expectedOffset = state.ReadOffset;
            int destinationIndex = 0;

            while (destinationIndex < destination.Length && GetBufferedSegmentCount(state) > 0)
            {
                BufferedSegment entry = GetBufferedSegment(state, 0);
                if (entry.Offset > expectedOffset)
                {
                    break;
                }

                if (entry.Offset < expectedOffset)
                {
                    int skip = (int)(expectedOffset - entry.Offset);
                    if (skip >= entry.Length)
                    {
                        DecreaseBufferedReadableBytes(state, entry.Length);
                        RemoveBufferedSegmentAt(state, 0);
                        continue;
                    }

                    entry = entry.Slice(skip);
                }

                int bytesToCopy = Math.Min(entry.Length, destination.Length - destinationIndex);
                entry.DataSpan[..bytesToCopy].CopyTo(destination[destinationIndex..]);
                destinationIndex += bytesToCopy;
                expectedOffset += (ulong)bytesToCopy;
                DecreaseBufferedReadableBytes(state, bytesToCopy);

                if (bytesToCopy == entry.Length)
                {
                    RemoveBufferedSegmentAt(state, 0);
                }
                else
                {
                    SetBufferedSegment(state, 0, entry.Slice(bytesToCopy));
                    break;
                }
            }

            if (destinationIndex == 0)
            {
                completed = state.ReceiveFinalSize.HasValue && state.ReadOffset == state.ReceiveFinalSize.Value;
                return false;
            }

            state.ReadOffset = expectedOffset;
            bytesWritten = destinationIndex;
            ulong increasedStreamLimit = IncreaseLimit(state.ReceiveLimit, (ulong)destinationIndex);
            if (increasedStreamLimit != state.ReceiveLimit)
            {
                state.ReceiveLimit = increasedStreamLimit;
                maxStreamDataFrame = new QuicMaxStreamDataFrame(streamIdValue, state.ReceiveLimit);
            }

            ulong increasedConnectionLimit = IncreaseLimit(ConnectionReceiveLimit, (ulong)destinationIndex);
            if (increasedConnectionLimit != ConnectionReceiveLimit)
            {
                ConnectionReceiveLimit = increasedConnectionLimit;
                maxDataFrame = new QuicMaxDataFrame(ConnectionReceiveLimit);
            }

            UpdateReceiveState(state);
            completed = state.ReceiveState == QuicStreamReceiveState.DataRead;
            return true;
        }
    }

    public bool TryAcknowledgeReset(ulong streamIdValue)
    {
        lock (syncRoot)
        {
            if (!streams.TryGetValue(streamIdValue, out StreamState? state) || state.ReceiveState != QuicStreamReceiveState.ResetRecvd)
            {
                return false;
            }

            state.ReceiveState = QuicStreamReceiveState.ResetRead;
            return true;
        }
    }

    public bool TryAcknowledgeSendCompletion(ulong streamIdValue)
    {
        lock (syncRoot)
        {
            if (!streams.TryGetValue(streamIdValue, out StreamState? state))
            {
                return false;
            }

            switch (state.SendState)
            {
                case QuicStreamSendState.DataSent:
                    state.SendState = QuicStreamSendState.DataRecvd;
                    return true;
                case QuicStreamSendState.ResetSent:
                    state.SendState = QuicStreamSendState.ResetRecvd;
                    return true;
                default:
                    return false;
            }
        }
    }

    public bool TryGetReceiveAbortErrorCode(ulong streamIdValue, out ulong applicationErrorCode)
    {
        lock (syncRoot)
        {
            applicationErrorCode = 0;
            if (!streams.TryGetValue(streamIdValue, out StreamState? state)
                || !state.HasReceiveAbortErrorCode)
            {
                return false;
            }

            applicationErrorCode = state.ReceiveAbortErrorCode;
            return true;
        }
    }

    public bool TryGetSendAbortErrorCode(ulong streamIdValue, out ulong applicationErrorCode)
    {
        lock (syncRoot)
        {
            applicationErrorCode = 0;
            if (!streams.TryGetValue(streamIdValue, out StreamState? state)
                || !state.HasSendAbortErrorCode)
            {
                return false;
            }

            applicationErrorCode = state.SendAbortErrorCode;
            return true;
        }
    }

    public bool TryGetStreamPriority(ulong streamIdValue, out int priority)
    {
        lock (syncRoot)
        {
            priority = default;
            if (!streams.TryGetValue(streamIdValue, out StreamState? state))
            {
                return false;
            }

            priority = state.Priority;
            return true;
        }
    }

    public bool TrySetStreamPriority(ulong streamIdValue, int priority)
    {
        lock (syncRoot)
        {
            if (!streams.TryGetValue(streamIdValue, out StreamState? state))
            {
                return false;
            }

            state.Priority = priority;
            return true;
        }
    }

    public bool TryGetStreamSnapshot(ulong streamIdValue, out QuicConnectionStreamSnapshot snapshot)
    {
        lock (syncRoot)
        {
            snapshot = default;
            if (!streams.TryGetValue(streamIdValue, out StreamState? state))
            {
                return false;
            }

            ulong? observableFinalSize = state.ReceiveFinalSize ?? state.SendFinalSize;

            snapshot = new QuicConnectionStreamSnapshot(
                streamIdValue,
                state.StreamType,
                state.SendState,
                state.ReceiveState,
                state.SendLimit,
                state.ReceiveLimit,
                observableFinalSize.GetValueOrDefault(),
                observableFinalSize.HasValue,
                state.SentRanges.TotalLength,
                state.ReceivedRanges.TotalLength,
                state.AccountedBytes,
                state.ReadOffset,
                state.BufferedReadableBytes,
                HasContiguousReadableBytes(state),
                state.ReceiveAbortErrorCode,
                state.HasReceiveAbortErrorCode,
                state.SendAbortErrorCode,
                state.HasSendAbortErrorCode,
                state.ReceivedZeroRttData,
                state.ReceivedOneRttData);
            return true;
        }
    }

    internal QuicReceiveRetentionSnapshot CaptureReceiveRetentionSnapshot()
    {
        lock (syncRoot)
        {
            return new QuicReceiveRetentionSnapshot(
                retainedReceiveBufferCount,
                retainedReceiveBufferBytes,
                bufferedReadableBytes,
                bufferedReadableStreamCount);
        }
    }

    public bool TryCaptureSendState(ulong streamIdValue, out QuicConnectionStreamSendStateSnapshot snapshot)
    {
        lock (syncRoot)
        {
            snapshot = default;
            if (!streams.TryGetValue(streamIdValue, out StreamState? state))
            {
                return false;
            }

            snapshot = CaptureSendState(streamIdValue, state);
            return true;
        }
    }

    private QuicConnectionStreamSendStateSnapshot CaptureSendState(ulong streamIdValue, StreamState state)
        => new(
            streamIdValue,
            connectionUniqueBytesSent,
            state.SendState,
            state.SendFinalSize,
            state.HighestSentOffset,
            state.SentRanges.CaptureSnapshot());

    public bool TryRestoreSendState(QuicConnectionStreamSendStateSnapshot snapshot)
    {
        lock (syncRoot)
        {
            if (!streams.TryGetValue(snapshot.StreamId, out StreamState? state))
            {
                return false;
            }

            connectionUniqueBytesSent = snapshot.ConnectionUniqueBytesSent;
            state.SendState = snapshot.SendState;
            state.SendFinalSize = snapshot.SendFinalSize;
            state.HighestSentOffset = snapshot.HighestSentOffset;
            state.SentRanges.Restore(snapshot.SentRanges);
            return true;
        }
    }

    private static void ValidateLimits(QuicConnectionStreamStateOptions options)
    {
        ValidateFlowControlLimit(options.InitialConnectionReceiveLimit);
        ValidateFlowControlLimit(options.InitialConnectionSendLimit);
        ValidateFlowControlLimit(options.InitialLocalBidirectionalReceiveLimit);
        ValidateFlowControlLimit(options.InitialPeerBidirectionalReceiveLimit);
        ValidateFlowControlLimit(options.InitialPeerUnidirectionalReceiveLimit);
        ValidateFlowControlLimit(options.InitialLocalBidirectionalSendLimit);
        ValidateFlowControlLimit(options.InitialLocalUnidirectionalSendLimit);
        ValidateFlowControlLimit(options.InitialPeerBidirectionalSendLimit);
        ValidateStreamCount(options.InitialIncomingBidirectionalStreamLimit);
        ValidateStreamCount(options.InitialIncomingUnidirectionalStreamLimit);
        ValidateStreamCount(options.InitialPeerBidirectionalStreamLimit);
        ValidateStreamCount(options.InitialPeerUnidirectionalStreamLimit);
    }

    private static int GetInitialTrackedStreamCapacity(QuicConnectionStreamStateOptions options)
    {
        ulong incomingCapacity = SaturatingAdd(
            options.InitialIncomingBidirectionalStreamLimit,
            options.InitialIncomingUnidirectionalStreamLimit);
        ulong peerCapacity = SaturatingAdd(
            options.InitialPeerBidirectionalStreamLimit,
            options.InitialPeerUnidirectionalStreamLimit);
        ulong estimatedCapacity = SaturatingAdd(incomingCapacity, peerCapacity);
        return (int)Math.Min(estimatedCapacity, MaximumInitialTrackedStreamCapacity);
    }

    private void EnsureTrackedStreamCapacity()
    {
        ulong incomingCapacity = SaturatingAdd(
            incomingBidirectionalStreamLimit,
            incomingUnidirectionalStreamLimit);
        ulong peerCapacity = SaturatingAdd(
            peerBidirectionalStreamLimit,
            peerUnidirectionalStreamLimit);
        ulong estimatedCapacity = SaturatingAdd(incomingCapacity, peerCapacity);
        if (estimatedCapacity == 0)
        {
            return;
        }

        streams.EnsureCapacity((int)Math.Min(estimatedCapacity, MaximumInitialTrackedStreamCapacity));
    }

    private static ulong SaturatingAdd(ulong left, ulong right)
    {
        ulong sum = left + right;
        return sum < left ? ulong.MaxValue : sum;
    }

    private static void ValidateFlowControlLimit(ulong value)
    {
        if (value > MaximumFlowControlLimit)
        {
            throw new ArgumentOutOfRangeException(nameof(value));
        }
    }

    private static void ValidateStreamCount(ulong value)
    {
        if (value > MaximumStreamCount)
        {
            throw new ArgumentOutOfRangeException(nameof(value));
        }
    }

    private bool TryResolveReceiveCapableStream(QuicStreamId streamId, [NotNullWhen(true)] out StreamState? state, out QuicTransportErrorCode errorCode)
    {
        errorCode = default;
        if (streams.TryGetValue(streamId.Value, out state))
        {
            if (!state.HasReceivePart)
            {
                errorCode = QuicTransportErrorCode.StreamStateError;
                return false;
            }

            return true;
        }

        if (IsPeerInitiated(streamId))
        {
            return TryOpenIncomingStreamSequence(streamId, out state, out errorCode);
        }

        errorCode = QuicTransportErrorCode.StreamStateError;
        return false;
    }

    private bool TryResolveSendCapableStream(QuicStreamId streamId, bool allowImplicitPeerOpen, [NotNullWhen(true)] out StreamState? state, out QuicTransportErrorCode errorCode)
    {
        errorCode = default;
        if (streams.TryGetValue(streamId.Value, out state))
        {
            if (!state.HasSendPart)
            {
                errorCode = QuicTransportErrorCode.StreamStateError;
                return false;
            }

            return true;
        }

        if (allowImplicitPeerOpen && IsPeerInitiated(streamId) && streamId.IsBidirectional)
        {
            return TryOpenIncomingStreamSequence(streamId, out state, out errorCode);
        }

        errorCode = QuicTransportErrorCode.StreamStateError;
        return false;
    }

    private bool TryResolveOrOpenLocalSendCapableStream(QuicStreamId streamId, [NotNullWhen(true)] out StreamState? state, out QuicTransportErrorCode errorCode)
    {
        errorCode = default;
        if (streams.TryGetValue(streamId.Value, out state))
        {
            if (!state.HasSendPart)
            {
                errorCode = QuicTransportErrorCode.StreamStateError;
                return false;
            }

            return true;
        }

        if (!IsLocalInitiated(streamId))
        {
            errorCode = QuicTransportErrorCode.StreamStateError;
            return false;
        }

        bool bidirectional = streamId.IsBidirectional;
        if (!TryPeekLocalStream(bidirectional, out QuicStreamId nextStreamId, out QuicStreamsBlockedFrame blockedFrame))
        {
            _ = blockedFrame;
            errorCode = QuicTransportErrorCode.StreamLimitError;
            return false;
        }

        if (nextStreamId.Value != streamId.Value)
        {
            errorCode = QuicTransportErrorCode.StreamStateError;
            return false;
        }

        if (!TryOpenLocalStream(bidirectional, out QuicStreamId committedStreamId, out QuicStreamsBlockedFrame committedBlockedFrame))
        {
            _ = committedBlockedFrame;
            errorCode = QuicTransportErrorCode.StreamLimitError;
            return false;
        }

        if (committedStreamId.Value != streamId.Value || !streams.TryGetValue(streamId.Value, out state))
        {
            errorCode = QuicTransportErrorCode.StreamStateError;
            return false;
        }

        return true;
    }

    private bool TryOpenIncomingStreamSequence(QuicStreamId streamId, [NotNullWhen(true)] out StreamState? state, out QuicTransportErrorCode errorCode)
    {
        state = default;
        errorCode = default;

        ulong streamIndex = streamId.Value >> 2;
        ulong limit = streamId.IsBidirectional ? incomingBidirectionalStreamLimit : incomingUnidirectionalStreamLimit;
        if (streamIndex >= limit)
        {
            errorCode = QuicTransportErrorCode.StreamLimitError;
            return false;
        }

        ulong startIndex = TryGetHighestCreatedIncomingStreamIndex(streamId.StreamType, out ulong highestCreatedIndex)
            ? highestCreatedIndex + 1
            : 0;

        for (ulong index = startIndex; index <= streamIndex; index++)
        {
            ulong value = BuildPeerStreamIdValue(streamId.IsBidirectional, index);
            streams.TryAdd(value, CreatePeerStreamState(new QuicStreamId(value)));
        }

        SetHighestCreatedIncomingStreamIndex(streamId.StreamType, streamIndex);
        state = streams[streamId.Value];
        return true;
    }

    private bool TryGetHighestCreatedIncomingStreamIndex(QuicStreamType streamType, out ulong highestCreatedIndex)
    {
        if (streamType == QuicStreamType.Bidirectional)
        {
            highestCreatedIndex = highestCreatedIncomingBidirectionalStreamIndex;
            return hasCreatedIncomingBidirectionalStream;
        }

        highestCreatedIndex = highestCreatedIncomingUnidirectionalStreamIndex;
        return hasCreatedIncomingUnidirectionalStream;
    }

    private void SetHighestCreatedIncomingStreamIndex(QuicStreamType streamType, ulong streamIndex)
    {
        if (streamType == QuicStreamType.Bidirectional)
        {
            highestCreatedIncomingBidirectionalStreamIndex = streamIndex;
            hasCreatedIncomingBidirectionalStream = true;
            return;
        }

        highestCreatedIncomingUnidirectionalStreamIndex = streamIndex;
        hasCreatedIncomingUnidirectionalStream = true;
    }

    private StreamState CreateLocalStreamState(QuicStreamId streamId)
    {
        return streamId.IsBidirectional
            ? new StreamState(streamId.StreamType, true, true, QuicStreamSendState.Ready, QuicStreamReceiveState.Recv, localBidirectionalSendLimit, initialLocalBidirectionalReceiveLimit, priority: 0)
            : new StreamState(streamId.StreamType, true, false, QuicStreamSendState.Ready, QuicStreamReceiveState.None, localUnidirectionalSendLimit, 0, priority: 0);
    }

    private StreamState CreatePeerStreamState(QuicStreamId streamId)
    {
        return streamId.IsBidirectional
            ? new StreamState(streamId.StreamType, true, true, QuicStreamSendState.Ready, QuicStreamReceiveState.Recv, peerBidirectionalSendLimit, initialPeerBidirectionalReceiveLimit, priority: 0)
            : new StreamState(streamId.StreamType, false, true, QuicStreamSendState.None, QuicStreamReceiveState.Recv, 0, initialPeerUnidirectionalReceiveLimit, priority: 0);
    }

    private ulong ResolveCurrentSendLimit(QuicStreamId streamId)
    {
        if (IsLocalInitiated(streamId))
        {
            return streamId.IsBidirectional
                ? localBidirectionalSendLimit
                : localUnidirectionalSendLimit;
        }

        return streamId.IsBidirectional
            ? peerBidirectionalSendLimit
            : 0;
    }

    private ulong ResolveCurrentReceiveLimit(QuicStreamId streamId)
    {
        if (IsLocalInitiated(streamId))
        {
            return streamId.IsBidirectional
                ? initialLocalBidirectionalReceiveLimit
                : 0;
        }

        return streamId.IsBidirectional
            ? initialPeerBidirectionalReceiveLimit
            : initialPeerUnidirectionalReceiveLimit;
    }

    private static bool ViolatesKnownReceiveFinalSize(StreamState state, ulong offset, ulong endExclusive, int length, bool fin)
    {
        if (!state.ReceiveFinalSize.HasValue)
        {
            return false;
        }

        ulong finalSize = state.ReceiveFinalSize.Value;
        return (fin && endExclusive != finalSize)
            || endExclusive > finalSize
            || (length > 0 && offset >= finalSize);
    }

    private static void UpdateReceiveState(StreamState state)
    {
        if (!state.HasReceivePart || state.ReceiveState is QuicStreamReceiveState.ResetRecvd or QuicStreamReceiveState.ResetRead || !state.ReceiveFinalSize.HasValue)
        {
            return;
        }

        state.ReceiveState = QuicStreamReceiveState.SizeKnown;
        if (state.ReceivedRanges.CoversPrefix(state.ReceiveFinalSize.Value))
        {
            state.ReceiveState = QuicStreamReceiveState.DataRecvd;
        }

        if (state.ReadOffset == state.ReceiveFinalSize.Value)
        {
            state.ReceiveState = QuicStreamReceiveState.DataRead;
            ReleaseBufferedSegmentScratch(state);
        }
    }

    private static ulong IncreaseLimit(ulong currentLimit, ulong delta)
    {
        if (delta == 0 || currentLimit == MaximumFlowControlLimit)
        {
            return currentLimit;
        }

        ulong remaining = MaximumFlowControlLimit - currentLimit;
        return currentLimit + Math.Min(remaining, delta);
    }

    private bool IsPeerInitiated(QuicStreamId streamId)
    {
        return isServer ? streamId.IsClientInitiated : streamId.IsServerInitiated;
    }

    private bool IsLocalInitiated(QuicStreamId streamId)
    {
        return isServer ? streamId.IsServerInitiated : streamId.IsClientInitiated;
    }

    private static bool IsStreamReceiveClosed(QuicStreamReceiveState receiveState)
        => receiveState is QuicStreamReceiveState.DataRead or QuicStreamReceiveState.ResetRead;

    private static bool IsStreamSendClosed(QuicStreamSendState sendState)
    {
        return sendState is QuicStreamSendState.DataSent
            or QuicStreamSendState.DataRecvd
            or QuicStreamSendState.ResetSent
            or QuicStreamSendState.ResetRecvd;
    }

    private static bool IsStreamSendClosedForNewFrames(QuicStreamSendState sendState)
    {
        return sendState is QuicStreamSendState.DataRecvd
            or QuicStreamSendState.ResetSent
            or QuicStreamSendState.ResetRecvd;
    }

    private static bool IsPeerStreamFullyClosed(StreamState state)
    {
        if (state.HasReceivePart && !IsStreamReceiveClosed(state.ReceiveState))
        {
            return false;
        }

        if (state.HasSendPart && !IsStreamSendClosed(state.SendState))
        {
            return false;
        }

        return true;
    }

    private ulong BuildLocalStreamIdValue(bool bidirectional, ulong streamIndex)
    {
        ulong initiatorBit = isServer ? 1UL : 0UL;
        ulong directionBit = bidirectional ? 0UL : UnidirectionalBit;
        return (streamIndex << StreamIdTypeBitCount) | initiatorBit | directionBit;
    }

    private ulong BuildPeerStreamIdValue(bool bidirectional, ulong streamIndex)
    {
        ulong initiatorBit = isServer ? 0UL : 1UL;
        ulong directionBit = bidirectional ? 0UL : UnidirectionalBit;
        return (streamIndex << StreamIdTypeBitCount) | initiatorBit | directionBit;
    }

    private void InsertReadableBytes(StreamState state, ulong offset, ReadOnlySpan<byte> data)
    {
        if (data.Length == 0)
        {
            return;
        }

        if (offset < state.ReadOffset)
        {
            int trim = (int)(state.ReadOffset - offset);
            if (trim >= data.Length)
            {
                return;
            }

            offset = state.ReadOffset;
            data = data[trim..];
        }

        ulong currentOffset = offset;
        ulong endOffset = offset + (ulong)data.Length;
        int dataIndex = 0;
        int currentIndex = 0;
        int bufferedSegmentCount = GetBufferedSegmentCount(state);
        if (bufferedSegmentCount == 0)
        {
            AddBufferedSegment(
                state,
                CreateBufferedSegment(currentOffset, data, dataIndex, data.Length, useContinuationBlock: false));
            IncreaseBufferedReadableBytes(state, data.Length);
            return;
        }

        BufferedSegment lastSegment = GetBufferedSegment(state, bufferedSegmentCount - 1);
        if (TryAppendBufferedSegment(state, bufferedSegmentCount - 1, lastSegment, currentOffset, data))
        {
            IncreaseBufferedReadableBytes(state, data.Length);
            return;
        }

        if (lastSegment.End <= currentOffset)
        {
            AddBufferedSegment(
                state,
                CreateBufferedSegment(
                    currentOffset,
                    data,
                    dataIndex,
                    data.Length,
                    useContinuationBlock: lastSegment.End == currentOffset));
            IncreaseBufferedReadableBytes(state, data.Length);
            return;
        }

        BufferedSegment tailSegment = lastSegment;
        if (tailSegment.Offset <= currentOffset
            && currentOffset < tailSegment.End
            && tailSegment.End < endOffset)
        {
            int tailDataIndex = (int)(tailSegment.End - offset);
            int tailLength = (int)(endOffset - tailSegment.End);
            if (TryAppendBufferedSegment(
                    state,
                    bufferedSegmentCount - 1,
                    tailSegment,
                    tailSegment.End,
                    data.Slice(tailDataIndex, tailLength)))
            {
                IncreaseBufferedReadableBytes(state, tailLength);
                return;
            }

            AddBufferedSegment(
                state,
                CreateBufferedSegment(
                    tailSegment.End,
                    data,
                    tailDataIndex,
                    tailLength,
                    useContinuationBlock: true));
            IncreaseBufferedReadableBytes(state, tailLength);
            return;
        }

        List<BufferedSegment> updated = state.BufferedSegmentScratch ??= RentBufferedSegmentList(bufferedSegmentCount + 2);
        updated.Clear();
        int expectedUpdatedCount = bufferedSegmentCount + 2;
        if (updated.Capacity < expectedUpdatedCount)
        {
            updated.EnsureCapacity(expectedUpdatedCount);
        }

        while (currentIndex < bufferedSegmentCount && GetBufferedSegment(state, currentIndex).End <= currentOffset)
        {
            updated.Add(GetBufferedSegment(state, currentIndex++));
        }

        while (currentIndex < bufferedSegmentCount && currentOffset < endOffset)
        {
            BufferedSegment existing = GetBufferedSegment(state, currentIndex);
            if (existing.Offset > currentOffset)
            {
                ulong gapEnd = Math.Min(existing.Offset, endOffset);
                int gapLength = (int)(gapEnd - currentOffset);
                if (gapLength > 0)
                {
                    updated.Add(CreateBufferedSegment(
                        currentOffset,
                        data,
                        dataIndex,
                        gapLength,
                        useContinuationBlock: false));
                    IncreaseBufferedReadableBytes(state, gapLength);
                    dataIndex += gapLength;
                    currentOffset += (ulong)gapLength;
                }
            }

            if (currentOffset >= endOffset)
            {
                break;
            }

            if (existing.End > currentOffset)
            {
                ulong skipEnd = Math.Min(existing.End, endOffset);
                if (skipEnd > currentOffset)
                {
                    dataIndex += (int)(skipEnd - currentOffset);
                    currentOffset = skipEnd;
                }
            }

            updated.Add(existing);
            currentIndex++;
        }

        if (currentOffset < endOffset)
        {
            int tailLength = (int)(endOffset - currentOffset);
            updated.Add(CreateBufferedSegment(
                currentOffset,
                data,
                dataIndex,
                tailLength,
                useContinuationBlock: false));
            IncreaseBufferedReadableBytes(state, tailLength);
        }

        while (currentIndex < bufferedSegmentCount)
        {
            updated.Add(GetBufferedSegment(state, currentIndex++));
        }

        ReplaceBufferedSegments(state, updated);
    }

    private static int GetBufferedSegmentCount(StreamState state)
    {
        if (state.BufferedSegmentList is { } segments)
        {
            return segments.Count;
        }

        if (state.HasSecondInlineBufferedSegment)
        {
            return InlineBufferedSegmentCapacity;
        }

        return state.HasInlineBufferedSegment ? 1 : 0;
    }

    private static BufferedSegment GetBufferedSegment(StreamState state, int index)
    {
        if (state.BufferedSegmentList is { } segments)
        {
            return segments[index];
        }

        if (state.HasInlineBufferedSegment)
        {
            return index switch
            {
                0 => state.InlineBufferedSegment,
                1 when state.HasSecondInlineBufferedSegment => state.SecondInlineBufferedSegment,
                _ => throw new ArgumentOutOfRangeException(nameof(index)),
            };
        }

        throw new ArgumentOutOfRangeException(nameof(index));
    }

    private static void SetBufferedSegment(StreamState state, int index, BufferedSegment segment)
    {
        if (state.BufferedSegmentList is { } segments)
        {
            segments[index] = segment;
            return;
        }

        if (state.HasInlineBufferedSegment)
        {
            switch (index)
            {
                case 0:
                    state.InlineBufferedSegment = segment;
                    return;
                case 1 when state.HasSecondInlineBufferedSegment:
                    state.SecondInlineBufferedSegment = segment;
                    return;
            }
        }

        throw new ArgumentOutOfRangeException(nameof(index));
    }

    private static void AddBufferedSegment(StreamState state, BufferedSegment segment)
    {
        if (state.BufferedSegmentList is { } segments)
        {
            segments.Add(segment);
            return;
        }

        if (!state.HasInlineBufferedSegment)
        {
            state.InlineBufferedSegment = segment;
            state.HasInlineBufferedSegment = true;
            return;
        }

        if (!state.HasSecondInlineBufferedSegment)
        {
            state.SecondInlineBufferedSegment = segment;
            state.HasSecondInlineBufferedSegment = true;
            return;
        }

        List<BufferedSegment> promotedSegments;
        if (state.BufferedSegmentScratch is { } scratch)
        {
            state.BufferedSegmentScratch = null;
            scratch.Clear();
            scratch.EnsureCapacity(SpilledBufferedSegmentInitialCapacity);
            promotedSegments = scratch;
        }
        else
        {
            promotedSegments = RentBufferedSegmentList(SpilledBufferedSegmentInitialCapacity);
        }

        promotedSegments.Add(state.InlineBufferedSegment);
        promotedSegments.Add(state.SecondInlineBufferedSegment);
        promotedSegments.Add(segment);
        state.BufferedSegmentList = promotedSegments;
        state.InlineBufferedSegment = default;
        state.SecondInlineBufferedSegment = default;
        state.HasInlineBufferedSegment = false;
        state.HasSecondInlineBufferedSegment = false;
    }

    private static bool TryAppendBufferedSegment(
        StreamState state,
        int index,
        BufferedSegment segment,
        ulong offset,
        ReadOnlySpan<byte> data)
    {
        int appendOffset = segment.DataOffset + segment.Length;
        if (segment.End != offset
            || !segment.OwnsData
            || data.Length > segment.Data.Length - appendOffset)
        {
            return false;
        }

        data.CopyTo(segment.Data.AsSpan(appendOffset));
        SetBufferedSegment(state, index, segment with { Length = segment.Length + data.Length });
        return true;
    }

    private static void ReplaceBufferedSegments(StreamState state, List<BufferedSegment> segments)
    {
        List<BufferedSegment>? previousActiveSegments = state.BufferedSegmentList;
        state.BufferedSegmentList = null;
        state.InlineBufferedSegment = default;
        state.SecondInlineBufferedSegment = default;
        state.HasInlineBufferedSegment = false;
        state.HasSecondInlineBufferedSegment = false;

        switch (segments.Count)
        {
            case 0:
                break;
            case 1:
                state.InlineBufferedSegment = segments[0];
                state.HasInlineBufferedSegment = true;
                break;
            case InlineBufferedSegmentCapacity:
                state.InlineBufferedSegment = segments[0];
                state.SecondInlineBufferedSegment = segments[1];
                state.HasInlineBufferedSegment = true;
                state.HasSecondInlineBufferedSegment = true;
                break;
            default:
                previousActiveSegments?.Clear();
                state.BufferedSegmentList = segments;
                state.BufferedSegmentScratch = previousActiveSegments;
                return;
        }

        segments.Clear();
        if (previousActiveSegments is not null
            && previousActiveSegments.Capacity > segments.Capacity)
        {
            previousActiveSegments.Clear();
            state.BufferedSegmentScratch = previousActiveSegments;
            ReturnBufferedSegmentList(segments);
            return;
        }

        state.BufferedSegmentScratch = segments;
        if (previousActiveSegments is not null)
        {
            ReturnBufferedSegmentList(previousActiveSegments);
        }
    }

    private static void ClearBufferedSegmentStorage(StreamState state)
    {
        List<BufferedSegment>? activeSegments = state.BufferedSegmentList;
        List<BufferedSegment>? scratchSegments = state.BufferedSegmentScratch;
        state.BufferedSegmentList = null;
        state.BufferedSegmentScratch = null;
        state.InlineBufferedSegment = default;
        state.SecondInlineBufferedSegment = default;
        state.HasInlineBufferedSegment = false;
        state.HasSecondInlineBufferedSegment = false;

        if (activeSegments is not null)
        {
            ReturnBufferedSegmentList(activeSegments);
        }

        if (scratchSegments is not null && !ReferenceEquals(activeSegments, scratchSegments))
        {
            ReturnBufferedSegmentList(scratchSegments);
        }
    }

    private BufferedSegment CreateBufferedSegment(
        ulong offset,
        ReadOnlySpan<byte> data,
        int dataIndex,
        int length,
        bool useContinuationBlock)
    {
        int receiveBlockSize = useContinuationBlock
            ? ContinuationStreamReceiveBlockSize
            : InitialStreamReceiveBlockSize;
        int minimumCapacity = length >= StreamReceiveCoalescingThreshold && length < receiveBlockSize
            ? receiveBlockSize
            : length;
        byte[] segmentData = QuicBufferPool.RentBytes(
            minimumCapacity,
            QuicBufferPoolOwner.ReceiveSegment);
        data.Slice(dataIndex, length).CopyTo(segmentData);
        retainedReceiveBufferCount++;
        retainedReceiveBufferBytes += segmentData.Length;
        return new BufferedSegment(offset, segmentData, DataOffset: 0, Length: length, OwnsData: true);
    }

    private void RemoveBufferedSegmentAt(StreamState state, int index)
    {
        BufferedSegment segment = GetBufferedSegment(state, index);
        DecreaseRetainedReceiveBuffers(segment);
        segment.Release();
        if (state.BufferedSegmentList is { } segments)
        {
            segments.RemoveAt(index);
            if (segments.Count <= InlineBufferedSegmentCapacity)
            {
                if (segments.Count >= 1)
                {
                    state.InlineBufferedSegment = segments[0];
                    state.HasInlineBufferedSegment = true;
                }

                if (segments.Count == InlineBufferedSegmentCapacity)
                {
                    state.SecondInlineBufferedSegment = segments[1];
                    state.HasSecondInlineBufferedSegment = true;
                }

                state.BufferedSegmentList = null;
                RetainBufferedSegmentScratch(state, segments);
            }

            return;
        }

        if (index == 0 && state.HasInlineBufferedSegment)
        {
            if (state.HasSecondInlineBufferedSegment)
            {
                state.InlineBufferedSegment = state.SecondInlineBufferedSegment;
                state.SecondInlineBufferedSegment = default;
                state.HasSecondInlineBufferedSegment = false;
            }
            else
            {
                state.InlineBufferedSegment = default;
                state.HasInlineBufferedSegment = false;
            }

            return;
        }

        if (index == 1 && state.HasSecondInlineBufferedSegment)
        {
            state.SecondInlineBufferedSegment = default;
            state.HasSecondInlineBufferedSegment = false;
            return;
        }

        throw new ArgumentOutOfRangeException(nameof(index));
    }

    private static void RetainBufferedSegmentScratch(StreamState state, List<BufferedSegment> candidate)
    {
        candidate.Clear();
        if (ReferenceEquals(state.BufferedSegmentScratch, candidate))
        {
            return;
        }

        if (state.BufferedSegmentScratch is null
            || candidate.Capacity > state.BufferedSegmentScratch.Capacity)
        {
            if (state.BufferedSegmentScratch is { } previousScratch)
            {
                ReturnBufferedSegmentList(previousScratch);
            }

            state.BufferedSegmentScratch = candidate;
            return;
        }

        ReturnBufferedSegmentList(candidate);
    }

    private static List<BufferedSegment> RentBufferedSegmentList(int minimumCapacity)
    {
        List<BufferedSegment>? segments = cachedBufferedSegmentList;
        if (segments is not null)
        {
            cachedBufferedSegmentList = secondaryCachedBufferedSegmentList;
            secondaryCachedBufferedSegmentList = null;
            segments.EnsureCapacity(minimumCapacity);
            return segments;
        }

        return new List<BufferedSegment>(minimumCapacity);
    }

    private static void ReturnBufferedSegmentList(List<BufferedSegment> segments)
    {
        segments.Clear();
        if (segments.Capacity > MaximumCachedBufferedSegmentCapacity)
        {
            return;
        }

        if (ReferenceEquals(cachedBufferedSegmentList, segments)
            || ReferenceEquals(secondaryCachedBufferedSegmentList, segments))
        {
            return;
        }

        if (cachedBufferedSegmentList is null)
        {
            cachedBufferedSegmentList = segments;
            return;
        }

        if (secondaryCachedBufferedSegmentList is null)
        {
            if (segments.Capacity > cachedBufferedSegmentList.Capacity)
            {
                secondaryCachedBufferedSegmentList = cachedBufferedSegmentList;
                cachedBufferedSegmentList = segments;
            }
            else
            {
                secondaryCachedBufferedSegmentList = segments;
            }

            return;
        }

        if (segments.Capacity > cachedBufferedSegmentList.Capacity)
        {
            secondaryCachedBufferedSegmentList = cachedBufferedSegmentList;
            cachedBufferedSegmentList = segments;
        }
        else if (segments.Capacity > secondaryCachedBufferedSegmentList.Capacity)
        {
            secondaryCachedBufferedSegmentList = segments;
        }
    }

    private static void ReleaseBufferedSegmentScratch(StreamState state)
    {
        if (state.BufferedSegmentScratch is not { } scratch)
        {
            return;
        }

        state.BufferedSegmentScratch = null;
        ReturnBufferedSegmentList(scratch);
    }

    private void ReleaseBufferedSegments(StreamState state)
    {
        int count = GetBufferedSegmentCount(state);
        for (int index = 0; index < count; index++)
        {
            BufferedSegment segment = GetBufferedSegment(state, index);
            DecreaseRetainedReceiveBuffers(segment);
            segment.Release();
        }

        ClearBufferedSegmentStorage(state);
    }

    private void IncreaseBufferedReadableBytes(StreamState state, int count)
    {
        if (count <= 0)
        {
            return;
        }

        if (state.BufferedReadableBytes == 0)
        {
            bufferedReadableStreamCount++;
        }

        state.BufferedReadableBytes += count;
        bufferedReadableBytes += count;
    }

    private void DecreaseBufferedReadableBytes(StreamState state, int count)
    {
        if (count <= 0)
        {
            return;
        }

        state.BufferedReadableBytes -= count;
        bufferedReadableBytes -= count;
        if (state.BufferedReadableBytes == 0)
        {
            bufferedReadableStreamCount--;
        }
    }

    private void DecreaseRetainedReceiveBuffers(BufferedSegment segment)
    {
        if (!segment.OwnsData)
        {
            return;
        }

        retainedReceiveBufferCount--;
        retainedReceiveBufferBytes -= segment.Data.Length;
    }

    private static bool HasContiguousReadableBytes(StreamState state)
    {
        return GetBufferedSegmentCount(state) > 0
            && GetBufferedSegment(state, 0).Offset <= state.ReadOffset
            && GetBufferedSegment(state, 0).End > state.ReadOffset;
    }

    private sealed class StreamState(
        QuicStreamType streamType,
        bool hasSendPart,
        bool hasReceivePart,
        QuicStreamSendState sendState,
        QuicStreamReceiveState receiveState,
        ulong sendLimit,
        ulong receiveLimit,
        int priority)
    {
        public QuicStreamType StreamType { get; } = streamType;
        public bool HasSendPart { get; } = hasSendPart;
        public bool HasReceivePart { get; } = hasReceivePart;
        public QuicStreamSendState SendState { get; set; } = sendState;
        public QuicStreamReceiveState ReceiveState { get; set; } = receiveState;
        public ulong SendLimit { get; set; } = sendLimit;
        public ulong ReceiveLimit { get; set; } = receiveLimit;
        public int Priority { get; set; } = priority;
        public ulong? SendFinalSize { get; set; }
        public ulong? ReceiveFinalSize { get; set; }
        public ulong AccountedBytes { get; set; }
        public ulong ReadOffset { get; set; }
        public int BufferedReadableBytes { get; set; }
        public ulong HighestSentOffset { get; set; }
        public ulong HighestReceivedOffset { get; set; }
        public ulong ReceiveAbortErrorCode { get; set; }
        public bool HasReceiveAbortErrorCode { get; set; }
        public ulong SendAbortErrorCode { get; set; }
        public bool HasSendAbortErrorCode { get; set; }
        public bool LocalStopSendingFrameSent { get; set; }
        public bool PeerCapacityReleaseReported { get; set; }
        public bool PeerAcceptQueued { get; set; }
        public QuicByteRangeSet SentRanges = new();
        public QuicByteRangeSet ReceivedRanges = new();
        public BufferedSegment InlineBufferedSegment { get; set; }
        public BufferedSegment SecondInlineBufferedSegment { get; set; }
        public bool HasInlineBufferedSegment { get; set; }
        public bool HasSecondInlineBufferedSegment { get; set; }
        public List<BufferedSegment>? BufferedSegmentList { get; set; }
        public List<BufferedSegment>? BufferedSegmentScratch { get; set; }
        public bool ReceivedZeroRttData { get; set; }
        public bool ReceivedOneRttData { get; set; }
    }

    private readonly record struct BufferedSegment(ulong Offset, byte[] Data, int DataOffset, int Length, bool OwnsData)
    {
        public BufferedSegment(ulong offset, byte[] data)
            : this(offset, data, 0, data.Length, OwnsData: false)
        {
        }

        public ulong End => Offset + (ulong)Length;

        public ReadOnlySpan<byte> DataSpan => Data.AsSpan(DataOffset, Length);

        public BufferedSegment Slice(int bytesConsumed)
        {
            return new BufferedSegment(
                Offset + (ulong)bytesConsumed,
                Data,
                DataOffset + bytesConsumed,
                Length - bytesConsumed,
                OwnsData);
        }

        public void Release()
        {
            if (OwnsData)
            {
                QuicBufferPool.ReturnBytes(Data);
            }
        }
    }
}

internal readonly record struct QuicConnectionStreamSendStateSnapshot(
    ulong StreamId,
    ulong ConnectionUniqueBytesSent,
    QuicStreamSendState SendState,
    ulong? SendFinalSize,
    ulong HighestSentOffset,
    QuicByteRangeSetSnapshot SentRanges);

internal readonly record struct QuicConnectionStreamWritePreparation(
    ulong WriteOffset,
    QuicConnectionStreamSendStateSnapshot SendStateBeforeWrite);

internal enum QuicConnectionStreamWritePreparationStatus
{
    Reserved,
    Unavailable,
    NotWritable,
    Completed,
    Blocked,
    Error,
}
