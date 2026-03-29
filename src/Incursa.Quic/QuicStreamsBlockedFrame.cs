namespace Incursa.Quic;

/// <summary>
/// A parsed or constructed STREAMS_BLOCKED frame.
/// </summary>
public readonly struct QuicStreamsBlockedFrame
{
    /// <summary>
    /// Initializes a STREAMS_BLOCKED frame view.
    /// </summary>
    public QuicStreamsBlockedFrame(bool isBidirectional, ulong maximumStreams)
    {
        IsBidirectional = isBidirectional;
        MaximumStreams = maximumStreams;
    }

    /// <summary>
    /// Gets whether the frame applies to bidirectional streams.
    /// </summary>
    public bool IsBidirectional { get; }

    /// <summary>
    /// Gets the maximum number of streams allowed at the time the frame was sent.
    /// </summary>
    public ulong MaximumStreams { get; }
}
