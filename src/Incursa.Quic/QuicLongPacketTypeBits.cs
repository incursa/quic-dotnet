namespace Incursa.Quic;

/// <summary>
/// Long-header packet type values from the RFC 9000 packet-type field.
/// </summary>
internal static class QuicLongPacketTypeBits
{
    /// <summary>
    /// The Initial packet type value.
    /// </summary>
    internal const byte Initial = 0x00;

    /// <summary>
    /// The 0-RTT packet type value.
    /// </summary>
    internal const byte ZeroRtt = 0x01;

    /// <summary>
    /// The Handshake packet type value.
    /// </summary>
    internal const byte Handshake = 0x02;

    /// <summary>
    /// The Retry packet type value.
    /// </summary>
    internal const byte Retry = 0x03;
}
