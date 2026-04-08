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
