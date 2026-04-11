namespace Incursa.Quic;

/// <summary>
/// A parsed or constructed MAX_DATA frame.
/// </summary>
internal readonly struct QuicMaxDataFrame
{
    /// <summary>
    /// Initializes a MAX_DATA frame view.
    /// </summary>
    internal QuicMaxDataFrame(ulong maximumData)
    {
        MaximumData = maximumData;
    }

    /// <summary>
    /// Gets the maximum connection-wide data limit.
    /// </summary>
    internal ulong MaximumData { get; }
}

