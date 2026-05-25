namespace Incursa.Quic.Http3;

/// <summary>
/// HTTP/3 application error codes registered by RFC 9114.
/// </summary>
public enum Http3ErrorCode : long
{
    /// <summary>
    /// No error occurred.
    /// </summary>
    NoError = 0x0100,

    /// <summary>
    /// Peer violated protocol requirements in a way not covered by a more specific code.
    /// </summary>
    GeneralProtocolError = 0x0101,

    /// <summary>
    /// Internal implementation error.
    /// </summary>
    InternalError = 0x0102,

    /// <summary>
    /// Peer violated stream creation requirements.
    /// </summary>
    StreamCreationError = 0x0103,

    /// <summary>
    /// A critical stream was closed.
    /// </summary>
    ClosedCriticalStream = 0x0104,

    /// <summary>
    /// A frame appeared where it is not permitted.
    /// </summary>
    FrameUnexpected = 0x0105,

    /// <summary>
    /// A frame was malformed.
    /// </summary>
    FrameError = 0x0106,

    /// <summary>
    /// Peer generated excessive load.
    /// </summary>
    ExcessiveLoad = 0x0107,

    /// <summary>
    /// Stream ID or Push ID was invalid.
    /// </summary>
    IdError = 0x0108,

    /// <summary>
    /// SETTINGS frame or settings usage was invalid.
    /// </summary>
    SettingsError = 0x0109,

    /// <summary>
    /// A required SETTINGS frame was missing.
    /// </summary>
    MissingSettings = 0x010A,

    /// <summary>
    /// A request was rejected before application processing.
    /// </summary>
    RequestRejected = 0x010B,

    /// <summary>
    /// A request was cancelled.
    /// </summary>
    RequestCancelled = 0x010C,

    /// <summary>
    /// A request or response ended before completion.
    /// </summary>
    RequestIncomplete = 0x010D,

    /// <summary>
    /// An HTTP message was malformed.
    /// </summary>
    MessageError = 0x010E,

    /// <summary>
    /// TCP connection established through CONNECT was reset or abnormal.
    /// </summary>
    ConnectError = 0x010F,

    /// <summary>
    /// Requested operation cannot be served over HTTP/3.
    /// </summary>
    VersionFallback = 0x0110,
}
