// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

// CONTEXT: This blocked-notification type stays separate from MAX_DATA because it reports where
// progress stalled, not a new credit grant, and that distinction matters to flow-control logic.
// SEE: QuicMaxDataFrame
/// <summary>
/// A parsed or constructed DATA_BLOCKED frame.
/// </summary>
internal readonly struct QuicDataBlockedFrame
{
    /// <summary>
    /// Initializes a DATA_BLOCKED frame view.
    /// </summary>
    internal QuicDataBlockedFrame(ulong maximumData)
    {
        MaximumData = maximumData;
    }

    /// <summary>
    /// Gets the maximum connection-wide data limit at which blocking occurred.
    /// </summary>
    internal ulong MaximumData { get; }
}
