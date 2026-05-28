// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

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

