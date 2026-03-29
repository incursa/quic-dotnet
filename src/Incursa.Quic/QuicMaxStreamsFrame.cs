namespace Incursa.Quic;

/// <summary>
/// A parsed or constructed MAX_STREAMS frame.
/// </summary>
public readonly struct QuicMaxStreamsFrame
{
    /// <summary>
    /// Initializes a MAX_STREAMS frame view.
    /// </summary>
    public QuicMaxStreamsFrame(bool isBidirectional, ulong maximumStreams)
    {
        IsBidirectional = isBidirectional;
        MaximumStreams = maximumStreams;
    }

    /// <summary>
    /// Gets whether the frame advertises a bidirectional stream limit.
    /// </summary>
    public bool IsBidirectional { get; }

    /// <summary>
    /// Gets the advertised stream limit.
    /// </summary>
    public ulong MaximumStreams { get; }
}
