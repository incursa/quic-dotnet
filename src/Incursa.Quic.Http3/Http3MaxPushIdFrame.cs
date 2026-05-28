// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Represents an HTTP/3 MAX_PUSH_ID frame.
/// </summary>
public sealed class Http3MaxPushIdFrame : Http3IdFrame
{
    /// <summary>
    /// Initializes a new instance of the <see cref="Http3MaxPushIdFrame" /> class.
    /// </summary>
    public Http3MaxPushIdFrame(ulong pushId, byte[] payload)
        : base((ulong)Http3FrameType.MaxPushId, pushId, payload)
    {
    }

    /// <summary>
    /// Gets the maximum Push ID.
    /// </summary>
    public ulong PushId => Identifier;
}
