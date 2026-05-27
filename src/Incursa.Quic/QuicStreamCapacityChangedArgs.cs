namespace Incursa.Quic;

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
