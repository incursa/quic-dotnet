// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

// CONTEXT: Connection-wide credit updates stay in their own type because the MAX_DATA wire shape
// is distinct from the corresponding BLOCKED notification and the parser/writer rely on that split.
// SEE: QuicDataBlockedFrame
/// <summary>
/// A parsed or constructed MAX_DATA frame.
/// </summary>
internal readonly struct QuicMaxDataFrame
{
    /// <summary>
    /// Initializes a MAX_DATA frame view.
    /// </summary>
    internal QuicMaxDataFrame(ulong maximumData)
    {
        MaximumData = maximumData;
    }

    /// <summary>
    /// Gets the maximum connection-wide data limit.
    /// </summary>
    internal ulong MaximumData { get; }
}
