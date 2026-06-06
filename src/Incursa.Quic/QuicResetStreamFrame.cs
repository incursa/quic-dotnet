// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

// CONTEXT: The stream ID, application error code, and final size stay in wire order because
// RESET_STREAM teardown depends on the peer seeing the original final size.
// SEE: QuicStream
/// <summary>
/// A parsed or constructed RESET_STREAM frame.
/// </summary>
internal readonly struct QuicResetStreamFrame
{
    /// <summary>
    /// Initializes a RESET_STREAM frame view.
    /// </summary>
    internal QuicResetStreamFrame(ulong streamId, ulong applicationProtocolErrorCode, ulong finalSize)
    {
        StreamId = streamId;
        ApplicationProtocolErrorCode = applicationProtocolErrorCode;
        FinalSize = finalSize;
    }

    /// <summary>
    /// Gets the stream identifier.
    /// </summary>
    internal ulong StreamId { get; }

    /// <summary>
    /// Gets the application protocol error code.
    /// </summary>
    internal ulong ApplicationProtocolErrorCode { get; }

    /// <summary>
    /// Gets the final size value.
    /// </summary>
    internal ulong FinalSize { get; }
}
