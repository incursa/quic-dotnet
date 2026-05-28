// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

internal sealed class FakeMonotonicClock : IMonotonicClock
{
    public FakeMonotonicClock(long ticks)
    {
        Ticks = ticks;
    }

    public long Ticks { get; private set; }

    public double Seconds => Ticks / (double)TimeSpan.TicksPerSecond;

    public void Advance(long ticks)
    {
        Ticks += ticks;
    }
}
