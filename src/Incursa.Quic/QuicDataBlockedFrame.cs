namespace Incursa.Quic;

/// <summary>
/// A parsed or constructed DATA_BLOCKED frame.
/// </summary>
public readonly struct QuicDataBlockedFrame
{
    /// <summary>
    /// Initializes a DATA_BLOCKED frame view.
    /// </summary>
    public QuicDataBlockedFrame(ulong maximumData)
    {
        MaximumData = maximumData;
    }

    /// <summary>
    /// Gets the maximum connection-wide data limit at which blocking occurred.
    /// </summary>
    public ulong MaximumData { get; }
}
