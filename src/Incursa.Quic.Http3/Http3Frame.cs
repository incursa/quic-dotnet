// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Base type for parsed HTTP/3 frames.
/// </summary>
public abstract class Http3Frame
{
    private protected Http3Frame(ulong type, byte[] payload)
    {
        Type = type;
        Payload = payload;
    }

    /// <summary>
    /// Gets the raw HTTP/3 frame type.
    /// </summary>
    public ulong Type { get; }

    /// <summary>
    /// Gets the exact frame payload bytes.
    /// </summary>
    public byte[] Payload { get; }

    /// <summary>
    /// Gets the payload length.
    /// </summary>
    public ulong Length => checked((ulong)Payload.Length);

    /// <summary>
    /// Gets a value indicating whether this frame uses a reserved frame type.
    /// </summary>
    public bool IsReserved => Http3FrameTypes.IsReserved(Type);
}
