namespace Incursa.Quic;

/// <summary>
/// A parsed or constructed MAX_DATA frame.
/// </summary>
public readonly struct QuicMaxDataFrame
{
    /// <summary>
    /// Initializes a MAX_DATA frame view.
    /// </summary>
    public QuicMaxDataFrame(ulong maximumData)
    {
        MaximumData = maximumData;
    }

    /// <summary>
    /// Gets the maximum connection-wide data limit.
    /// </summary>
    public ulong MaximumData { get; }
}
