namespace Incursa.Quic;

/// <summary>
/// Parsed ECN counters carried by ACK frame type 0x03.
/// </summary>
public readonly struct QuicEcnCounts
{
    /// <summary>
    /// Initializes a new ECN counter set.
    /// </summary>
    public QuicEcnCounts(ulong ect0Count, ulong ect1Count, ulong ecnCeCount)
    {
        Ect0Count = ect0Count;
        Ect1Count = ect1Count;
        EcnCeCount = ecnCeCount;
    }

    /// <summary>
    /// Gets the ECT(0) count.
    /// </summary>
    public ulong Ect0Count { get; }

    /// <summary>
    /// Gets the ECT(1) count.
    /// </summary>
    public ulong Ect1Count { get; }

    /// <summary>
    /// Gets the ECN-CE count.
    /// </summary>
    public ulong EcnCeCount { get; }
}
