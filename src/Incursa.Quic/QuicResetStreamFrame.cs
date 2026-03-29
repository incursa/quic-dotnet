namespace Incursa.Quic;

/// <summary>
/// A parsed or constructed RESET_STREAM frame.
/// </summary>
public readonly struct QuicResetStreamFrame
{
    /// <summary>
    /// Initializes a RESET_STREAM frame view.
    /// </summary>
    public QuicResetStreamFrame(ulong streamId, ulong applicationProtocolErrorCode, ulong finalSize)
    {
        StreamId = streamId;
        ApplicationProtocolErrorCode = applicationProtocolErrorCode;
        FinalSize = finalSize;
    }

    /// <summary>
    /// Gets the stream identifier.
    /// </summary>
    public ulong StreamId { get; }

    /// <summary>
    /// Gets the application protocol error code.
    /// </summary>
    public ulong ApplicationProtocolErrorCode { get; }

    /// <summary>
    /// Gets the final size value.
    /// </summary>
    public ulong FinalSize { get; }
}
