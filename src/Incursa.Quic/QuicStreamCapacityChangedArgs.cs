namespace Incursa.Quic;

/// <summary>
/// Arguments passed to <see cref="QuicConnectionOptions.StreamCapacityCallback"/>.
/// </summary>
public readonly struct QuicStreamCapacityChangedArgs
{
    /// <summary>
    /// Gets the additional bidirectional stream capacity that became available.
    /// </summary>
    public int BidirectionalIncrement { get; init; }

    /// <summary>
    /// Gets the additional unidirectional stream capacity that became available.
    /// </summary>
    public int UnidirectionalIncrement { get; init; }
}
