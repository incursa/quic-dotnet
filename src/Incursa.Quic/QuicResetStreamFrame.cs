namespace Incursa.Quic;

/// <summary>
/// A parsed or constructed RESET_STREAM frame.
/// </summary>
internal readonly struct QuicResetStreamFrame
{
    /// <summary>
    /// Initializes a RESET_STREAM frame view.
    /// </summary>
    internal QuicResetStreamFrame(ulong streamId, ulong applicationProtocolErrorCode, ulong finalSize)
    {
        StreamId = streamId;
        ApplicationProtocolErrorCode = applicationProtocolErrorCode;
        FinalSize = finalSize;
    }

    /// <summary>
    /// Gets the stream identifier.
    /// </summary>
    internal ulong StreamId { get; }

    /// <summary>
    /// Gets the application protocol error code.
    /// </summary>
    internal ulong ApplicationProtocolErrorCode { get; }

    /// <summary>
    /// Gets the final size value.
    /// </summary>
    internal ulong FinalSize { get; }
}

