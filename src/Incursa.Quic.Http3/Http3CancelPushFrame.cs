namespace Incursa.Quic.Http3;

/// <summary>
/// Represents an HTTP/3 CANCEL_PUSH frame.
/// </summary>
public sealed class Http3CancelPushFrame : Http3IdFrame
{
    /// <summary>
    /// Initializes a new instance of the <see cref="Http3CancelPushFrame" /> class.
    /// </summary>
    public Http3CancelPushFrame(ulong pushId, byte[] payload)
        : base((ulong)Http3FrameType.CancelPush, pushId, payload)
    {
    }

    /// <summary>
    /// Gets the Push ID.
    /// </summary>
    public ulong PushId => Identifier;
}
