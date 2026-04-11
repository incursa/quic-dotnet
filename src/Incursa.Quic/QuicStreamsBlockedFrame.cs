namespace Incursa.Quic;

/// <summary>
/// A parsed or constructed STREAMS_BLOCKED frame.
/// </summary>
internal readonly struct QuicStreamsBlockedFrame
{
    /// <summary>
    /// Initializes a STREAMS_BLOCKED frame view.
    /// </summary>
    internal QuicStreamsBlockedFrame(bool isBidirectional, ulong maximumStreams)
    {
        IsBidirectional = isBidirectional;
        MaximumStreams = maximumStreams;
    }

    /// <summary>
    /// Gets whether the frame applies to bidirectional streams.
    /// </summary>
    internal bool IsBidirectional { get; }

    /// <summary>
    /// Gets the maximum number of streams allowed at the time the frame was sent.
    /// </summary>
    internal ulong MaximumStreams { get; }
}

