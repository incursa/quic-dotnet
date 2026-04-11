namespace Incursa.Quic;

/// <summary>
/// Identifies the version-independent QUIC packet header form.
/// </summary>
internal enum QuicHeaderForm
{
    /// <summary>
    /// A packet with the first byte high bit cleared.
    /// </summary>
    Short = 0,

    /// <summary>
    /// A packet with the first byte high bit set.
    /// </summary>
    Long = 1,
}

