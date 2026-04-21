using System.Diagnostics.CodeAnalysis;

namespace Incursa.Quic;

internal sealed class QuicConnectionStreamState
{
    private const ulong MaximumFlowControlLimit = QuicVariableLengthInteger.MaxValue;
    private const ulong MaximumStreamCount = 1UL << 60;
    private const ulong UnidirectionalBit = 0x02;
    private const int StreamIdTypeBitCount = 2;

    private readonly bool isServer;
    private readonly Dictionary<ulong, StreamState> streams = [];
    private readonly Dictionary<QuicStreamType, ulong> highestCreatedIncomingStreamIndexes = [];

    private readonly ulong initialLocalBidirectionalReceiveLimit;
    private readonly ulong initialPeerBidirectionalReceiveLimit;
    private readonly ulong initialPeerUnidirectionalReceiveLimit;
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

    public QuicConnectionStreamState(QuicConnectionStreamStateOptions options)
    {
        ValidateLimits(options);

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

    public bool TryPeekLocalStream(bool bidirectional, out QuicStreamId streamId, out QuicStreamsBlockedFrame blockedFrame)
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

    public bool TryOpenLocalStream(bool bidirectional, out QuicStreamId streamId, out QuicStreamsBlockedFrame blockedFrame)
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

    public bool TryApplyMaxDataFrame(QuicMaxDataFrame frame)
    {
        if (frame.MaximumData <= ConnectionSendLimit)
        {
            return false;
        }

        ConnectionSendLimit = frame.MaximumData;
        return true;
    }

    public bool TryApplyMaxStreamsFrame(QuicMaxStreamsFrame frame)
    {
        if (frame.IsBidirectional)
        {
            if (frame.MaximumStreams <= peerBidirectionalStreamLimit)
            {
                return false;
            }

            peerBidirectionalStreamLimit = frame.MaximumStreams;
            return true;
        }

        if (frame.MaximumStreams <= peerUnidirectionalStreamLimit)
        {
            return false;
        }

        peerUnidirectionalStreamLimit = frame.MaximumStreams;
        return true;
    }

    public bool TryPeekPeerStreamCapacityRelease(ulong streamIdValue, out QuicMaxStreamsFrame frame)
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

    public bool TryCommitPeerStreamCapacityRelease(ulong streamIdValue, QuicMaxStreamsFrame frame)
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

    public bool TryApplyMaxStreamDataFrame(QuicMaxStreamDataFrame frame, out QuicTransportErrorCode errorCode)
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

    public bool TryApplyPeerTransportParameterSendLimits(
        ulong localBidirectionalLimit,
        ulong peerBidirectionalLimit,
        ulong localUnidirectionalLimit)
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

    public bool TryReserveSendCapacity(
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

        QuicStreamId streamId = new(streamIdValue);
        if (!TryResolveSendCapableStream(streamId, allowImplicitPeerOpen: false, out StreamState? state, out errorCode))
        {
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
        if (additionalBytes > 0 && additionalBytes > ConnectionSendLimit - connectionUniqueBytesSent)
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

    public bool TryReceiveStreamFrame(QuicStreamFrame frame, out QuicTransportErrorCode errorCode)
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

        if (frame.StreamDataLength > 0)
        {
            InsertReadableBytes(state, frame.Offset, frame.StreamData.ToArray());
        }

        UpdateReceiveState(state);
        return true;
    }

    public bool TryReceiveStreamDataBlockedFrame(
        QuicStreamDataBlockedFrame frame,
        out QuicTransportErrorCode errorCode)
    {
        QuicStreamId streamId = new(frame.StreamId);
        return TryResolveReceiveCapableStream(streamId, out _, out errorCode);
    }

    public bool TryReceiveResetStreamFrame(
        QuicResetStreamFrame frame,
        out QuicMaxDataFrame maxDataFrame,
        out QuicTransportErrorCode errorCode)
        => TryReceiveResetStreamFrame(frame, out maxDataFrame, out errorCode, suppressResetSignalWhenDataRecvd: false);

    internal bool TryReceiveResetStreamFrame(
        QuicResetStreamFrame frame,
        out QuicMaxDataFrame maxDataFrame,
        out QuicTransportErrorCode errorCode,
        bool suppressResetSignalWhenDataRecvd)
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

        state.BufferedSegments.Clear();
        state.BufferedReadableBytes = 0;
        state.ReceiveFinalSize = frame.FinalSize;
        state.HighestReceivedOffset = Math.Max(state.HighestReceivedOffset, frame.FinalSize);
        state.AccountedBytes = newAccountedBytes;
        connectionAccountedBytesReceived += additionalAccountedBytes;
        state.ReceiveState = QuicStreamReceiveState.ResetRecvd;
        state.ReceiveAbortErrorCode = frame.ApplicationProtocolErrorCode;
        state.HasReceiveAbortErrorCode = true;
        return true;
    }

    public bool TryAbortLocalStreamWrites(
        ulong streamIdValue,
        out ulong finalSize,
        out QuicTransportErrorCode errorCode)
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

    public bool TryReceiveStopSendingFrame(
        QuicStopSendingFrame frame,
        out QuicResetStreamFrame resetStreamFrame,
        out QuicTransportErrorCode errorCode)
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

    public bool TryReadStreamData(
        ulong streamIdValue,
        Span<byte> destination,
        out int bytesWritten,
        out bool completed,
        out QuicMaxDataFrame maxDataFrame,
        out QuicMaxStreamDataFrame maxStreamDataFrame,
        out QuicTransportErrorCode errorCode)
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

        if (destination.IsEmpty || state.BufferedSegments.Count == 0)
        {
            completed = state.ReceiveFinalSize.HasValue && state.ReadOffset == state.ReceiveFinalSize.Value;
            return false;
        }

        ulong expectedOffset = state.ReadOffset;
        int destinationIndex = 0;

        while (destinationIndex < destination.Length && state.BufferedSegments.Count > 0)
        {
            BufferedSegment entry = state.BufferedSegments[0];
            if (entry.Offset > expectedOffset)
            {
                break;
            }

            if (entry.Offset < expectedOffset)
            {
                int skip = (int)(expectedOffset - entry.Offset);
                if (skip >= entry.Data.Length)
                {
                    state.BufferedReadableBytes -= entry.Data.Length;
                    state.BufferedSegments.RemoveAt(0);
                    continue;
                }

                entry = new BufferedSegment(expectedOffset, entry.Data[skip..]);
            }

            int bytesToCopy = Math.Min(entry.Data.Length, destination.Length - destinationIndex);
            entry.Data.AsSpan(0, bytesToCopy).CopyTo(destination[destinationIndex..]);
            destinationIndex += bytesToCopy;
            expectedOffset += (ulong)bytesToCopy;
            state.BufferedReadableBytes -= bytesToCopy;

            if (bytesToCopy == entry.Data.Length)
            {
                state.BufferedSegments.RemoveAt(0);
            }
            else
            {
                state.BufferedSegments[0] = new BufferedSegment(entry.Offset + (ulong)bytesToCopy, entry.Data[bytesToCopy..]);
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

    public bool TryAcknowledgeReset(ulong streamIdValue)
    {
        if (!streams.TryGetValue(streamIdValue, out StreamState? state) || state.ReceiveState != QuicStreamReceiveState.ResetRecvd)
        {
            return false;
        }

        state.ReceiveState = QuicStreamReceiveState.ResetRead;
        return true;
    }

    public bool TryAcknowledgeSendCompletion(ulong streamIdValue)
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

    public bool TryGetReceiveAbortErrorCode(ulong streamIdValue, out ulong applicationErrorCode)
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

    public bool TryGetSendAbortErrorCode(ulong streamIdValue, out ulong applicationErrorCode)
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

    public bool TryGetStreamSnapshot(ulong streamIdValue, out QuicConnectionStreamSnapshot snapshot)
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
            state.ReceiveAbortErrorCode,
            state.HasReceiveAbortErrorCode,
            state.SendAbortErrorCode,
            state.HasSendAbortErrorCode);
        return true;
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

        highestCreatedIncomingStreamIndexes.TryGetValue(streamId.StreamType, out ulong highestCreatedIndex);
        ulong startIndex = highestCreatedIncomingStreamIndexes.ContainsKey(streamId.StreamType) ? highestCreatedIndex + 1 : 0;

        for (ulong index = startIndex; index <= streamIndex; index++)
        {
            ulong value = BuildPeerStreamIdValue(streamId.IsBidirectional, index);
            streams.TryAdd(value, CreatePeerStreamState(new QuicStreamId(value)));
        }

        highestCreatedIncomingStreamIndexes[streamId.StreamType] = streamIndex;
        state = streams[streamId.Value];
        return true;
    }

    private StreamState CreateLocalStreamState(QuicStreamId streamId)
    {
        return streamId.IsBidirectional
            ? new StreamState(streamId.StreamType, true, true, QuicStreamSendState.Ready, QuicStreamReceiveState.Recv, localBidirectionalSendLimit, initialLocalBidirectionalReceiveLimit)
            : new StreamState(streamId.StreamType, true, false, QuicStreamSendState.Ready, QuicStreamReceiveState.None, localUnidirectionalSendLimit, 0);
    }

    private StreamState CreatePeerStreamState(QuicStreamId streamId)
    {
        return streamId.IsBidirectional
            ? new StreamState(streamId.StreamType, true, true, QuicStreamSendState.Ready, QuicStreamReceiveState.Recv, peerBidirectionalSendLimit, initialPeerBidirectionalReceiveLimit)
            : new StreamState(streamId.StreamType, false, true, QuicStreamSendState.None, QuicStreamReceiveState.Recv, 0, initialPeerUnidirectionalReceiveLimit);
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

    private static void InsertReadableBytes(StreamState state, ulong offset, byte[] data)
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
        List<BufferedSegment> updated = new(state.BufferedSegments.Count + 2);

        while (currentIndex < state.BufferedSegments.Count && state.BufferedSegments[currentIndex].End <= currentOffset)
        {
            updated.Add(state.BufferedSegments[currentIndex++]);
        }

        while (currentIndex < state.BufferedSegments.Count && currentOffset < endOffset)
        {
            BufferedSegment existing = state.BufferedSegments[currentIndex];
            if (existing.Offset > currentOffset)
            {
                ulong gapEnd = Math.Min(existing.Offset, endOffset);
                int gapLength = (int)(gapEnd - currentOffset);
                if (gapLength > 0)
                {
                    updated.Add(new BufferedSegment(currentOffset, data[dataIndex..(dataIndex + gapLength)]));
                    state.BufferedReadableBytes += gapLength;
                    dataIndex += gapLength;
                    currentOffset += (ulong)gapLength;
                }
            }

            if (currentOffset >= endOffset)
            {
                break;
            }

            if (existing.Offset < currentOffset)
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
            updated.Add(new BufferedSegment(currentOffset, data[dataIndex..(dataIndex + tailLength)]));
            state.BufferedReadableBytes += tailLength;
        }

        while (currentIndex < state.BufferedSegments.Count)
        {
            updated.Add(state.BufferedSegments[currentIndex++]);
        }

        state.BufferedSegments.Clear();
        state.BufferedSegments.AddRange(updated);
    }

    private sealed class StreamState(
        QuicStreamType streamType,
        bool hasSendPart,
        bool hasReceivePart,
        QuicStreamSendState sendState,
        QuicStreamReceiveState receiveState,
        ulong sendLimit,
        ulong receiveLimit)
    {
        public QuicStreamType StreamType { get; } = streamType;
        public bool HasSendPart { get; } = hasSendPart;
        public bool HasReceivePart { get; } = hasReceivePart;
        public QuicStreamSendState SendState { get; set; } = sendState;
        public QuicStreamReceiveState ReceiveState { get; set; } = receiveState;
        public ulong SendLimit { get; set; } = sendLimit;
        public ulong ReceiveLimit { get; set; } = receiveLimit;
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
        public bool PeerCapacityReleaseReported { get; set; }
        public QuicByteRangeSet SentRanges { get; } = new();
        public QuicByteRangeSet ReceivedRanges { get; } = new();
        public List<BufferedSegment> BufferedSegments { get; } = [];
    }

    private readonly record struct BufferedSegment(ulong Offset, byte[] Data)
    {
        public ulong End => Offset + (ulong)Data.Length;
    }
}
