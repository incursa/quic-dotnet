namespace Incursa.Quic.Http3;

/// <summary>
/// Represents an HTTP/3 GOAWAY frame.
/// </summary>
public sealed class Http3GoAwayFrame : Http3IdFrame
{
    /// <summary>
    /// Initializes a new instance of the <see cref="Http3GoAwayFrame" /> class.
    /// </summary>
    public Http3GoAwayFrame(ulong streamOrPushId, byte[] payload)
        : base((ulong)Http3FrameType.GoAway, streamOrPushId, payload)
    {
    }

    /// <summary>
    /// Gets the Stream ID or Push ID carried by the frame.
    /// </summary>
    public ulong StreamOrPushId => Identifier;
}
