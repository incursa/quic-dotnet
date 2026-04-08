namespace Incursa.Quic;

/// <summary>
/// Provides monotonic time measurements for durations and timeouts.
/// </summary>
internal interface IMonotonicClock
{
    /// <summary>
    /// Gets the current monotonic time in high-resolution ticks.
    /// </summary>
    long Ticks { get; }

    /// <summary>
    /// Gets the current monotonic time in seconds.
    /// </summary>
    double Seconds { get; }
}
