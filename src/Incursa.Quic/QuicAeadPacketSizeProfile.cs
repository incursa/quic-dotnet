namespace Incursa.Quic;

/// <summary>
/// Describes the packet-size regimes used by the RFC 9001 Appendix B AEAD limit guidance.
/// </summary>
internal enum QuicAeadPacketSizeProfile
{
    /// <summary>
    /// The endpoint strictly limits packet sizes to 2^11 bytes.
    /// </summary>
    StrictlyLimitedToTwoPow11Bytes = 0,

    /// <summary>
    /// The endpoint allows packets as large as 2^16 bytes.
    /// </summary>
    AllowsPacketsAsLargeAsTwoPow16Bytes = 1,

    /// <summary>
    /// The endpoint does not restrict the packet size in the way described by the selected Appendix B clause.
    /// </summary>
    Unrestricted = 2,
}

