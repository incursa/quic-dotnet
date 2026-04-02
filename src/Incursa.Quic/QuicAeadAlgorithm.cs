namespace Incursa.Quic;

/// <summary>
/// Identifies the AEAD algorithms covered by the RFC 9001 Appendix B limit guidance in this library.
/// </summary>
public enum QuicAeadAlgorithm
{
    /// <summary>
    /// The AEAD_AES_128_GCM algorithm.
    /// </summary>
    Aes128Gcm = 0,

    /// <summary>
    /// The AEAD_AES_256_GCM algorithm.
    /// </summary>
    Aes256Gcm = 1,

    /// <summary>
    /// The AEAD_AES_128_CCM algorithm.
    /// </summary>
    Aes128Ccm = 2,
}
