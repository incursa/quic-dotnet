namespace Incursa.Quic;

/// <summary>
/// Identifies the explicit lifecycle phase of a connection runtime.
/// </summary>
internal enum QuicConnectionPhase
{
    Establishing = 0,
    Active = 1,
    Closing = 2,
    Draining = 3,
    Discarded = 4,
}
