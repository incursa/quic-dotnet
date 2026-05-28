// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Describes the HTTP/3 mapping for a QUIC stream.
/// </summary>
public sealed class Http3StreamInfo
{
    internal Http3StreamInfo(
        ulong streamId,
        Http3StreamInitiator initiator,
        Http3StreamDirection direction,
        Http3StreamKind kind,
        ulong? streamType)
    {
        StreamId = streamId;
        Initiator = initiator;
        Direction = direction;
        Kind = kind;
        StreamType = streamType;
    }

    /// <summary>
    /// Gets the QUIC stream ID.
    /// </summary>
    public ulong StreamId { get; }

    /// <summary>
    /// Gets the QUIC stream initiator.
    /// </summary>
    public Http3StreamInitiator Initiator { get; }

    /// <summary>
    /// Gets the QUIC stream direction.
    /// </summary>
    public Http3StreamDirection Direction { get; }

    /// <summary>
    /// Gets the HTTP/3 stream kind.
    /// </summary>
    public Http3StreamKind Kind { get; }

    /// <summary>
    /// Gets the unidirectional stream type when known.
    /// </summary>
    public ulong? StreamType { get; }
}
