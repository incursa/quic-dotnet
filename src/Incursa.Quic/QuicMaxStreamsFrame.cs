namespace Incursa.Quic;

/// <summary>
/// A parsed or constructed MAX_STREAMS frame.
/// </summary>
internal readonly struct QuicMaxStreamsFrame
{
    /// <summary>
    /// Initializes a MAX_STREAMS frame view.
    /// </summary>
    internal QuicMaxStreamsFrame(bool isBidirectional, ulong maximumStreams)
    {
        IsBidirectional = isBidirectional;
        MaximumStreams = maximumStreams;
    }

    /// <summary>
    /// Gets whether the frame advertises a bidirectional stream limit.
    /// </summary>
    internal bool IsBidirectional { get; }

    /// <summary>
    /// Gets the advertised stream limit.
    /// </summary>
    internal ulong MaximumStreams { get; }
}

