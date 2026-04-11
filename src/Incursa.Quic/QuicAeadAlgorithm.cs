namespace Incursa.Quic;

/// <summary>
/// Identifies the AEAD algorithms covered by the RFC 9001 Appendix B limit guidance in this library.
/// </summary>
internal enum QuicAeadAlgorithm
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

/// <summary>
/// Provides algorithm metadata for packet-protection material binding.
/// </summary>
internal static class QuicAeadAlgorithmMetadata
{
    /// <summary>
    /// The AEAD nonce length used by the supported QUIC packet-protection algorithms.
    /// </summary>
    private const int AeadNonceLength = 12;

    /// <summary>
    /// The key and header-protection key length used by AEAD_AES_128_* algorithms.
    /// </summary>
    private const int Aes128KeyLength = 16;

    /// <summary>
    /// The key and header-protection key length used by AEAD_AES_256_GCM.
    /// </summary>
    private const int Aes256KeyLength = 32;

    /// <summary>
    /// Gets the key, IV, and header-protection key lengths for a supported packet-protection AEAD.
    /// </summary>
    internal static bool TryGetPacketProtectionLengths(
        QuicAeadAlgorithm algorithm,
        out int aeadKeyLength,
        out int aeadIvLength,
        out int headerProtectionKeyLength)
    {
        aeadKeyLength = default;
        aeadIvLength = default;
        headerProtectionKeyLength = default;

        switch (algorithm)
        {
            case QuicAeadAlgorithm.Aes128Gcm:
            case QuicAeadAlgorithm.Aes128Ccm:
                aeadKeyLength = Aes128KeyLength;
                aeadIvLength = AeadNonceLength;
                headerProtectionKeyLength = Aes128KeyLength;
                return true;

            case QuicAeadAlgorithm.Aes256Gcm:
                aeadKeyLength = Aes256KeyLength;
                aeadIvLength = AeadNonceLength;
                headerProtectionKeyLength = Aes256KeyLength;
                return true;

            default:
                return false;
        }
    }
}

