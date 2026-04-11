namespace Incursa.Quic;

/// <summary>
/// A parsed or constructed STREAM_DATA_BLOCKED frame.
/// </summary>
internal readonly struct QuicStreamDataBlockedFrame
{
    /// <summary>
    /// Initializes a STREAM_DATA_BLOCKED frame view.
    /// </summary>
    internal QuicStreamDataBlockedFrame(ulong streamId, ulong maximumStreamData)
    {
        StreamId = streamId;
        MaximumStreamData = maximumStreamData;
    }

    /// <summary>
    /// Gets the blocked stream identifier.
    /// </summary>
    internal ulong StreamId { get; }

    /// <summary>
    /// Gets the stream data offset at which blocking occurred.
    /// </summary>
    internal ulong MaximumStreamData { get; }
}

