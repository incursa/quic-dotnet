// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

internal static class QuicMaxAckDelayPolicy
{
    internal const ulong DefaultIntentionalAckDelayMicros = 24_000UL;
    internal const ulong DefaultExpectedAlarmFiringDelayMicros = 1_000UL;
    internal const ulong DefaultMaxAckDelayMicros =
        DefaultIntentionalAckDelayMicros + DefaultExpectedAlarmFiringDelayMicros;

    internal static ulong IncludeExpectedAlarmFiringDelay(
        ulong intentionalAckDelayMicros,
        ulong expectedAlarmFiringDelayMicros)
    {
        return ulong.MaxValue - intentionalAckDelayMicros < expectedAlarmFiringDelayMicros
            ? ulong.MaxValue
            : intentionalAckDelayMicros + expectedAlarmFiringDelayMicros;
    }
}
