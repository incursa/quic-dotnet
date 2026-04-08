using System.Diagnostics;

namespace Incursa.Quic;

/// <summary>
/// Provides monotonic time measurements using <see cref="Stopwatch"/>.
/// </summary>
internal sealed class MonotonicClock : IMonotonicClock
{
    private static readonly double TicksToSeconds = 1.0 / Stopwatch.Frequency;

    /// <inheritdoc />
    public long Ticks => Stopwatch.GetTimestamp();

    /// <inheritdoc />
    public double Seconds => Ticks * TicksToSeconds;
}
