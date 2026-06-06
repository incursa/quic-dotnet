// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

// CONTEXT: The conversion rounds idle timeout up to whole milliseconds on the transport-parameter
// side, then back to runtime microseconds, so the two representations keep a conservative floor.
// SEE: IdleTimeoutToMaxIdleTimeoutMilliseconds and MaxIdleTimeoutMillisecondsToRuntimeMicros
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
