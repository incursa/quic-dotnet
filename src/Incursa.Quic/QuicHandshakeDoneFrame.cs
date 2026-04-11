namespace Incursa.Quic;

/// <summary>
/// A parsed or constructed HANDSHAKE_DONE frame.
/// </summary>
internal readonly struct QuicHandshakeDoneFrame
{
    /// <summary>
    /// RFC 9000 HANDSHAKE_DONE frame type.
    /// </summary>
    private const byte FrameTypeValue = 0x1E;

    /// <summary>
    /// Gets the frame type carried on the wire.
    /// </summary>
    internal byte FrameType => FrameTypeValue;
}

