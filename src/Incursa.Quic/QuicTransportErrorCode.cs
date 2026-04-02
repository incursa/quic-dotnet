using System.ComponentModel;

namespace Incursa.Quic;

/// <summary>
/// Identifies the defined QUIC transport error codes that may be carried in a CONNECTION_CLOSE frame of type 0x1c.
/// </summary>
public enum QuicTransportErrorCode : ulong
{
    /// <summary>
    /// The connection closed without an error.
    /// </summary>
    [Description("The connection closed without an error.")]
    NoError = 0x00,

    /// <summary>
    /// The endpoint encountered an internal error.
    /// </summary>
    [Description("The endpoint encountered an internal error.")]
    InternalError = 0x01,

    /// <summary>
    /// The server refused to accept the connection.
    /// </summary>
    [Description("The server refused to accept the connection.")]
    ConnectionRefused = 0x02,

    /// <summary>
    /// The peer violated the advertised flow control limits.
    /// </summary>
    [Description("The peer violated the advertised flow control limits.")]
    FlowControlError = 0x03,

    /// <summary>
    /// The peer opened too many streams.
    /// </summary>
    [Description("The peer opened too many streams.")]
    StreamLimitError = 0x04,

    /// <summary>
    /// The endpoint observed an invalid stream state transition.
    /// </summary>
    [Description("The endpoint observed an invalid stream state transition.")]
    StreamStateError = 0x05,

    /// <summary>
    /// The peer changed a stream's final size.
    /// </summary>
    [Description("The peer changed a stream's final size.")]
    FinalSizeError = 0x06,

    /// <summary>
    /// The peer encoded a frame incorrectly.
    /// </summary>
    [Description("The peer encoded a frame incorrectly.")]
    FrameEncodingError = 0x07,

    /// <summary>
    /// The peer violated transport-parameter processing rules.
    /// </summary>
    [Description("The peer violated transport-parameter processing rules.")]
    TransportParameterError = 0x08,

    /// <summary>
    /// The peer exceeded the active connection ID limit.
    /// </summary>
    [Description("The peer exceeded the active connection ID limit.")]
    ConnectionIdLimitError = 0x09,

    /// <summary>
    /// The peer violated a QUIC transport rule.
    /// </summary>
    [Description("The peer violated a QUIC transport rule.")]
    ProtocolViolation = 0x0A,

    /// <summary>
    /// The peer supplied an invalid token.
    /// </summary>
    [Description("The peer supplied an invalid token.")]
    InvalidToken = 0x0B,

    /// <summary>
    /// The application closed the connection.
    /// </summary>
    [Description("The application closed the connection.")]
    ApplicationError = 0x0C,

    /// <summary>
    /// The endpoint could not buffer all required CRYPTO data.
    /// </summary>
    [Description("The endpoint could not buffer all required CRYPTO data.")]
    CryptoBufferExceeded = 0x0D,

    /// <summary>
    /// The endpoint encountered a key update failure.
    /// </summary>
    [Description("The endpoint encountered a key update failure.")]
    KeyUpdateError = 0x0E,

    /// <summary>
    /// The endpoint reached the AEAD usage limit.
    /// </summary>
    [Description("The endpoint reached the AEAD usage limit.")]
    AeadLimitReached = 0x0F,

    /// <summary>
    /// The endpoint has no viable path to its peer.
    /// </summary>
    [Description("The endpoint has no viable path to its peer.")]
    NoViablePath = 0x10,
}
