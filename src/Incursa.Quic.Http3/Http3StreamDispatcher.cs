// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Maps QUIC streams to HTTP/3 stream roles and validates frame placement.
/// </summary>
public sealed class Http3StreamDispatcher
{
    private const ulong InitiatorMask = 0x01;
    private const ulong DirectionMask = 0x02;
    private const ulong ServerInitiatedBit = 0x01;
    private const ulong UnidirectionalBit = 0x02;
    private const ulong ReservedStreamTypeOffset = 0x21;
    private const ulong ReservedStreamTypeModulus = 0x1F;

    private readonly Dictionary<ulong, StreamState> streams = [];
    private readonly Dictionary<Http3StreamInitiator, ulong> controlStreamsByInitiator = [];
    private readonly bool allowServerInitiatedBidirectionalStreams;

    /// <summary>
    /// Initializes a new instance of the <see cref="Http3StreamDispatcher" /> class.
    /// </summary>
    public Http3StreamDispatcher(
        Http3EndpointRole localRole,
        bool allowServerInitiatedBidirectionalStreams = false,
        bool enableServerPush = false)
    {
        LocalRole = localRole;
        this.allowServerInitiatedBidirectionalStreams = allowServerInitiatedBidirectionalStreams;
        ServerPushEnabled = enableServerPush;
    }

    /// <summary>
    /// Gets the local endpoint role.
    /// </summary>
    public Http3EndpointRole LocalRole { get; }

    /// <summary>
    /// Gets a value indicating whether server push is enabled.
    /// </summary>
    public bool ServerPushEnabled { get; }

    /// <summary>
    /// Registers a bidirectional stream.
    /// </summary>
    public Http3StreamInfo RegisterBidirectionalStream(ulong streamId)
    {
        ValidateDirection(streamId, Http3StreamDirection.Bidirectional);
        Http3StreamInitiator initiator = GetInitiator(streamId);
        if (initiator == Http3StreamInitiator.Server && !allowServerInitiatedBidirectionalStreams)
        {
            throw new Http3Exception(Http3ErrorCode.StreamCreationError, "Server-initiated bidirectional HTTP/3 streams are not allowed.");
        }

        Http3StreamInfo info = new(streamId, initiator, Http3StreamDirection.Bidirectional, Http3StreamKind.Request, streamType: null);
        streams[streamId] = new StreamState(info);
        return info;
    }

    /// <summary>
    /// Registers a unidirectional stream. The stream kind is assigned after the stream type varint is received.
    /// </summary>
    public Http3StreamInfo RegisterUnidirectionalStream(ulong streamId)
    {
        ValidateDirection(streamId, Http3StreamDirection.Unidirectional);
        Http3StreamInfo info = new(
            streamId,
            GetInitiator(streamId),
            Http3StreamDirection.Unidirectional,
            Http3StreamKind.Unknown,
            streamType: null);
        streams[streamId] = new StreamState(info);
        return info;
    }

    /// <summary>
    /// Feeds bytes from the beginning of a unidirectional stream until the stream type is known.
    /// </summary>
    public Http3StreamInfo ReceiveUnidirectionalStreamTypeBytes(ulong streamId, ReadOnlySpan<byte> bytes, bool endOfStream = false)
    {
        StreamState state = GetExisting(streamId);
        if (state.Info.StreamType.HasValue)
        {
            return state.Info;
        }

        if (!TryReceiveUnidirectionalStreamTypeBytes(
            streamId,
            bytes,
            out Http3StreamInfo info,
            out int bytesConsumed,
            endOfStream))
        {
            return info;
        }

        if (bytesConsumed != bytes.Length)
        {
            throw new Http3Exception(
                Http3ErrorCode.StreamCreationError,
                "HTTP/3 stream type parsing must be completed before processing stream payload bytes.");
        }

        return info;
    }

    /// <summary>
    /// Feeds bytes from the beginning of a unidirectional stream and reports the bytes consumed by the stream type.
    /// </summary>
    public bool TryReceiveUnidirectionalStreamTypeBytes(
        ulong streamId,
        ReadOnlySpan<byte> bytes,
        out Http3StreamInfo info,
        out int bytesConsumed,
        bool endOfStream = false)
    {
        StreamState state = GetExisting(streamId);
        info = state.Info;
        bytesConsumed = 0;
        if (state.Info.Direction != Http3StreamDirection.Unidirectional)
        {
            throw new Http3Exception(Http3ErrorCode.StreamCreationError, "Bidirectional streams do not carry an HTTP/3 unidirectional stream type.");
        }

        if (state.Info.StreamType.HasValue)
        {
            return true;
        }

        int pendingLength = state.PendingStreamTypeBytes.Length;
        state.PendingStreamTypeBytes = Append(state.PendingStreamTypeBytes, bytes);
        if (!Http3VariableLengthInteger.TryParse(state.PendingStreamTypeBytes, out ulong streamType, out int parsedBytesConsumed))
        {
            if (endOfStream)
            {
                throw new Http3Exception(Http3ErrorCode.StreamCreationError, "The HTTP/3 unidirectional stream ended before its stream type.");
            }

            return false;
        }

        Http3StreamKind kind = MapStreamKind(streamType);
        ValidateUniqueStreamType(streamId, state.Info.Initiator, kind);
        if (kind == Http3StreamKind.Push && state.Info.Initiator != Http3StreamInitiator.Server)
        {
            throw new Http3Exception(Http3ErrorCode.StreamCreationError, "HTTP/3 push streams can only be server initiated.");
        }

        if (kind == Http3StreamKind.Push && !ServerPushEnabled)
        {
            throw new Http3Exception(Http3ErrorCode.IdError, "HTTP/3 push streams are disabled.");
        }

        state.Info = new Http3StreamInfo(
            streamId,
            state.Info.Initiator,
            Http3StreamDirection.Unidirectional,
            kind,
            streamType);
        state.PendingStreamTypeBytes = [];
        info = state.Info;
        bytesConsumed = Math.Max(0, parsedBytesConsumed - pendingLength);
        return true;
    }

    /// <summary>
    /// Processes a frame on the mapped HTTP/3 stream.
    /// </summary>
    public void ReceiveFrame(ulong streamId, Http3Frame frame)
    {
        ArgumentNullException.ThrowIfNull(frame);
        StreamState state = GetExisting(streamId);
        if (state.Info.Direction == Http3StreamDirection.Unidirectional && !state.Info.StreamType.HasValue)
        {
            throw new Http3Exception(Http3ErrorCode.StreamCreationError, "The HTTP/3 unidirectional stream type is not known.");
        }

        switch (state.Info.Kind)
        {
            case Http3StreamKind.Request:
                ValidateRequestStreamFrame(frame);
                break;
            case Http3StreamKind.Control:
                state.ControlState ??= new Http3ControlStreamState();
                state.ControlState.ReceiveFrame(frame);
                break;
            case Http3StreamKind.Push:
                ValidatePushStreamFrame(frame);
                break;
            case Http3StreamKind.QPackEncoder:
            case Http3StreamKind.QPackDecoder:
                throw new Http3Exception(Http3ErrorCode.FrameUnexpected, "QPACK streams do not carry HTTP/3 frames.");
            case Http3StreamKind.Unknown:
            case Http3StreamKind.Reserved:
                throw new Http3Exception(Http3ErrorCode.FrameUnexpected, "Unknown and reserved HTTP/3 streams do not carry HTTP/3 frames in this layer.");
            default:
                throw new Http3Exception(Http3ErrorCode.InternalError, "The HTTP/3 stream kind is invalid.");
        }
    }

    /// <summary>
    /// Gets the mapped stream state.
    /// </summary>
    public Http3StreamInfo GetStreamInfo(ulong streamId)
    {
        return GetExisting(streamId).Info;
    }

    /// <summary>
    /// Tries to get peer SETTINGS received on an endpoint's control stream.
    /// </summary>
    public bool TryGetControlStreamSettings(Http3StreamInitiator initiator, out Http3Settings? settings)
    {
        settings = null;
        if (!controlStreamsByInitiator.TryGetValue(initiator, out ulong streamId)
            || !streams.TryGetValue(streamId, out StreamState? state)
            || state.ControlState?.PeerSettings is null)
        {
            return false;
        }

        settings = state.ControlState.PeerSettings;
        return true;
    }

    private static Http3StreamInitiator GetInitiator(ulong streamId)
    {
        return (streamId & InitiatorMask) == ServerInitiatedBit
            ? Http3StreamInitiator.Server
            : Http3StreamInitiator.Client;
    }

    private static Http3StreamDirection GetDirection(ulong streamId)
    {
        return (streamId & DirectionMask) == UnidirectionalBit
            ? Http3StreamDirection.Unidirectional
            : Http3StreamDirection.Bidirectional;
    }

    private static Http3StreamKind MapStreamKind(ulong streamType)
    {
        return streamType switch
        {
            (ulong)Http3StreamType.Control => Http3StreamKind.Control,
            (ulong)Http3StreamType.QPackEncoder => Http3StreamKind.QPackEncoder,
            (ulong)Http3StreamType.QPackDecoder => Http3StreamKind.QPackDecoder,
            (ulong)Http3StreamType.Push => Http3StreamKind.Push,
            _ when IsReservedStreamType(streamType) => Http3StreamKind.Reserved,
            _ => Http3StreamKind.Unknown,
        };
    }

    private static bool IsReservedStreamType(ulong streamType)
    {
        return streamType >= ReservedStreamTypeOffset
            && (streamType - ReservedStreamTypeOffset) % ReservedStreamTypeModulus == 0;
    }

    private void ValidateRequestStreamFrame(Http3Frame frame)
    {
        if (frame is Http3PushPromiseFrame)
        {
            if (LocalRole == Http3EndpointRole.Server)
            {
                throw new Http3Exception(Http3ErrorCode.FrameUnexpected, "HTTP/3 clients must not send PUSH_PROMISE frames.");
            }

            if (!ServerPushEnabled)
            {
                throw new Http3Exception(Http3ErrorCode.IdError, "HTTP/3 PUSH_PROMISE requires client opt-in with MAX_PUSH_ID.");
            }

            return;
        }

        if (frame is not Http3DataFrame
            and not Http3HeadersFrame
            and not Http3UnknownFrame)
        {
            throw new Http3Exception(Http3ErrorCode.FrameUnexpected, "The HTTP/3 frame is not allowed on a request stream.");
        }
    }

    private static void ValidatePushStreamFrame(Http3Frame frame)
    {
        if (frame is not Http3DataFrame
            and not Http3HeadersFrame
            and not Http3UnknownFrame)
        {
            throw new Http3Exception(Http3ErrorCode.FrameUnexpected, "The HTTP/3 frame is not allowed on a push stream.");
        }
    }

    private static byte[] Append(byte[] pending, ReadOnlySpan<byte> source)
    {
        if (source.IsEmpty)
        {
            return pending;
        }

        byte[] combined = new byte[pending.Length + source.Length];
        pending.CopyTo(combined, 0);
        source.CopyTo(combined.AsSpan(pending.Length));
        return combined;
    }

    private void ValidateDirection(ulong streamId, Http3StreamDirection expectedDirection)
    {
        if (GetDirection(streamId) != expectedDirection)
        {
            throw new Http3Exception(Http3ErrorCode.StreamCreationError, "The QUIC stream direction does not match the HTTP/3 registration path.");
        }
    }

    private void ValidateUniqueStreamType(ulong streamId, Http3StreamInitiator initiator, Http3StreamKind kind)
    {
        if (kind != Http3StreamKind.Control)
        {
            return;
        }

        if (controlStreamsByInitiator.ContainsKey(initiator))
        {
            throw new Http3Exception(Http3ErrorCode.StreamCreationError, "Each HTTP/3 endpoint can create only one control stream.");
        }

        controlStreamsByInitiator.Add(initiator, streamId);
    }

    private StreamState GetExisting(ulong streamId)
    {
        if (!streams.TryGetValue(streamId, out StreamState? state))
        {
            throw new Http3Exception(Http3ErrorCode.StreamCreationError, "The HTTP/3 stream has not been registered.");
        }

        return state;
    }

    private sealed class StreamState
    {
        internal StreamState(Http3StreamInfo info)
        {
            Info = info;
        }

        internal Http3StreamInfo Info { get; set; }

        internal byte[] PendingStreamTypeBytes { get; set; } = [];

        internal Http3ControlStreamState? ControlState { get; set; }
    }
}
