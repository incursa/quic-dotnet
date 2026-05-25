namespace Incursa.Quic.Http3;

/// <summary>
/// HTTP/3 frame type values defined by RFC 9114.
/// </summary>
public enum Http3FrameType : long
{
    /// <summary>
    /// DATA frame.
    /// </summary>
    Data = 0x00,

    /// <summary>
    /// HEADERS frame.
    /// </summary>
    Headers = 0x01,

    /// <summary>
    /// CANCEL_PUSH frame.
    /// </summary>
    CancelPush = 0x03,

    /// <summary>
    /// SETTINGS frame.
    /// </summary>
    Settings = 0x04,

    /// <summary>
    /// PUSH_PROMISE frame.
    /// </summary>
    PushPromise = 0x05,

    /// <summary>
    /// GOAWAY frame.
    /// </summary>
    GoAway = 0x07,

    /// <summary>
    /// MAX_PUSH_ID frame.
    /// </summary>
    MaxPushId = 0x0D,
}
