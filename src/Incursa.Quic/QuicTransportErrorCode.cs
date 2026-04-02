namespace Incursa.Quic;

/// <summary>
/// Identifies the defined QUIC transport error codes that may be carried in a CONNECTION_CLOSE frame of type 0x1c.
/// </summary>
public enum QuicTransportErrorCode : ulong
{
    /// <summary>
    /// The connection closed without an error.
    /// </summary>
    NoError = 0x00,

    /// <summary>
    /// The endpoint encountered an internal error.
    /// </summary>
    InternalError = 0x01,

    /// <summary>
    /// The server refused to accept the connection.
    /// </summary>
    ConnectionRefused = 0x02,

    /// <summary>
    /// The peer violated the advertised flow control limits.
    /// </summary>
    FlowControlError = 0x03,

    /// <summary>
    /// The peer opened too many streams.
    /// </summary>
    StreamLimitError = 0x04,

    /// <summary>
    /// The endpoint observed an invalid stream state transition.
    /// </summary>
    StreamStateError = 0x05,

    /// <summary>
    /// The peer changed a stream's final size.
    /// </summary>
    FinalSizeError = 0x06,

    /// <summary>
    /// The peer encoded a frame incorrectly.
    /// </summary>
    FrameEncodingError = 0x07,

    /// <summary>
    /// The peer violated transport-parameter processing rules.
    /// </summary>
    TransportParameterError = 0x08,

    /// <summary>
    /// The peer exceeded the active connection ID limit.
    /// </summary>
    ConnectionIdLimitError = 0x09,

    /// <summary>
    /// The peer violated a QUIC transport rule.
    /// </summary>
    ProtocolViolation = 0x0A,

    /// <summary>
    /// The peer supplied an invalid token.
    /// </summary>
    InvalidToken = 0x0B,

    /// <summary>
    /// The application closed the connection.
    /// </summary>
    ApplicationError = 0x0C,

    /// <summary>
    /// The endpoint could not buffer all required CRYPTO data.
    /// </summary>
    CryptoBufferExceeded = 0x0D,

    /// <summary>
    /// The endpoint encountered a key update failure.
    /// </summary>
    KeyUpdateError = 0x0E,

    /// <summary>
    /// The endpoint reached the AEAD usage limit.
    /// </summary>
    AeadLimitReached = 0x0F,

    /// <summary>
    /// The endpoint has no viable path to its peer.
    /// </summary>
    NoViablePath = 0x10,
}
