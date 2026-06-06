// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

// CONTEXT: The clock is abstracted so timeout and pacing code can be driven by a deterministic
// test double instead of coupling directly to Stopwatch.
// SEE: MonotonicClock
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
