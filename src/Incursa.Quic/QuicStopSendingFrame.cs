namespace Incursa.Quic;

/// <summary>
/// A parsed or constructed STOP_SENDING frame.
/// </summary>
internal readonly struct QuicStopSendingFrame
{
    /// <summary>
    /// Initializes a STOP_SENDING frame view.
    /// </summary>
    internal QuicStopSendingFrame(ulong streamId, ulong applicationProtocolErrorCode)
    {
        StreamId = streamId;
        ApplicationProtocolErrorCode = applicationProtocolErrorCode;
    }

    /// <summary>
    /// Gets the stream identifier.
    /// </summary>
    internal ulong StreamId { get; }

    /// <summary>
    /// Gets the application protocol error code.
    /// </summary>
    internal ulong ApplicationProtocolErrorCode { get; }
}

