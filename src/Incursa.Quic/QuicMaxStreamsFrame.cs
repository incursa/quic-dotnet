// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

// CONTEXT: Bidirectional and unidirectional stream-count limits stay separate because MAX_STREAMS
// carries the grant while STREAMS_BLOCKED reports the limit that was actually hit.
// SEE: QuicStreamsBlockedFrame
/// <summary>
/// A parsed or constructed MAX_STREAMS frame.
/// </summary>
internal readonly struct QuicMaxStreamsFrame
{
    /// <summary>
    /// Initializes a MAX_STREAMS frame view.
    /// </summary>
    internal QuicMaxStreamsFrame(bool isBidirectional, ulong maximumStreams)
    {
        IsBidirectional = isBidirectional;
        MaximumStreams = maximumStreams;
    }

    /// <summary>
    /// Gets whether the frame advertises a bidirectional stream limit.
    /// </summary>
    internal bool IsBidirectional { get; }

    /// <summary>
    /// Gets the advertised stream limit.
    /// </summary>
    internal ulong MaximumStreams { get; }
}
