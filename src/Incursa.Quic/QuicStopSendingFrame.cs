namespace Incursa.Quic;

/// <summary>
/// A parsed or constructed STOP_SENDING frame.
/// </summary>
public readonly struct QuicStopSendingFrame
{
    /// <summary>
    /// Initializes a STOP_SENDING frame view.
    /// </summary>
    public QuicStopSendingFrame(ulong streamId, ulong applicationProtocolErrorCode)
    {
        StreamId = streamId;
        ApplicationProtocolErrorCode = applicationProtocolErrorCode;
    }

    /// <summary>
    /// Gets the stream identifier.
    /// </summary>
    public ulong StreamId { get; }

    /// <summary>
    /// Gets the application protocol error code.
    /// </summary>
    public ulong ApplicationProtocolErrorCode { get; }
}
