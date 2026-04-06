namespace Incursa.Quic;

/// <summary>
/// STREAM frame type values and type-specific flag bits from the RFC 9000 frame registry.
/// </summary>
internal static class QuicStreamFrameBits
{
    /// <summary>
    /// The minimum STREAM frame type value.
    /// </summary>
    internal const byte StreamFrameTypeMinimum = 0x08;

    /// <summary>
    /// The maximum STREAM frame type value.
    /// </summary>
    internal const byte StreamFrameTypeMaximum = 0x0F;

    /// <summary>
    /// The optional offset-present bit.
    /// </summary>
    internal const byte OffsetBitMask = 0x04;

    /// <summary>
    /// The optional length-present bit.
    /// </summary>
    internal const byte LengthBitMask = 0x02;

    /// <summary>
    /// The FIN bit.
    /// </summary>
    internal const byte FinBitMask = 0x01;
}
