namespace Incursa.Quic;

/// <summary>
/// A parsed or constructed DATA_BLOCKED frame.
/// </summary>
internal readonly struct QuicDataBlockedFrame
{
    /// <summary>
    /// Initializes a DATA_BLOCKED frame view.
    /// </summary>
    internal QuicDataBlockedFrame(ulong maximumData)
    {
        MaximumData = maximumData;
    }

    /// <summary>
    /// Gets the maximum connection-wide data limit at which blocking occurred.
    /// </summary>
    internal ulong MaximumData { get; }
}

