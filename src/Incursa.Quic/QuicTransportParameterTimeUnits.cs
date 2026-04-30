namespace Incursa.Quic;

internal static class QuicTransportParameterTimeUnits
{
    private const ulong MicrosecondsPerMillisecond = 1_000UL;

    internal static ulong IdleTimeoutToMaxIdleTimeoutMilliseconds(TimeSpan idleTimeout)
    {
        if (idleTimeout <= TimeSpan.Zero)
        {
            return 0;
        }

        return checked((ulong)((idleTimeout.Ticks + TimeSpan.TicksPerMillisecond - 1) / TimeSpan.TicksPerMillisecond));
    }

    internal static ulong? MaxIdleTimeoutMillisecondsToRuntimeMicros(ulong? maxIdleTimeoutMilliseconds)
        => maxIdleTimeoutMilliseconds.HasValue
            ? checked(maxIdleTimeoutMilliseconds.Value * MicrosecondsPerMillisecond)
            : null;
}
