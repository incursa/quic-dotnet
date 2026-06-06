// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

// CONTEXT: The bidirectional and unidirectional deltas are kept separate because stream credit is
// tracked independently and callers usually only need the newly available class.
// SEE: QuicListener
/// <summary>
/// Arguments passed to <see cref="QuicConnectionOptions.StreamCapacityCallback"/>.
/// </summary>
public readonly struct QuicStreamCapacityChangedArgs
{
    /// <summary>
    /// Gets the additional bidirectional stream capacity that became available.
    /// </summary>
    /// <remarks>
    /// Treat this as a backpressure signal for application work mapped to bidirectional streams.
    /// </remarks>
    public int BidirectionalIncrement { get; init; }

    /// <summary>
    /// Gets the additional unidirectional stream capacity that became available.
    /// </summary>
    /// <remarks>
    /// Treat this as a backpressure signal for application control streams or other unidirectional stream mappings.
    /// </remarks>
    public int UnidirectionalIncrement { get; init; }
}
