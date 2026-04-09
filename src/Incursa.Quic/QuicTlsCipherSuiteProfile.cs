using System.Security.Cryptography;
using System.Text;

namespace Incursa.Quic;

/// <summary>
/// Describes the narrow managed TLS 1.3 cipher-suite profile supported by the client-role key schedule slice.
/// </summary>
internal readonly struct QuicTlsCipherSuiteProfile
{
    private static readonly byte[] SupportedSubsetDescription = Encoding.ASCII.GetBytes("TLS_AES_128_GCM_SHA256 over secp256r1");

    private QuicTlsCipherSuiteProfile(
        QuicTlsCipherSuite cipherSuite,
        QuicTlsTranscriptHashAlgorithm transcriptHashAlgorithm,
        HashAlgorithmName transcriptHashAlgorithmName,
        QuicTlsNamedGroup namedGroup,
        QuicAeadAlgorithm packetProtectionAlgorithm)
    {
        CipherSuite = cipherSuite;
        TranscriptHashAlgorithm = transcriptHashAlgorithm;
        TranscriptHashAlgorithmName = transcriptHashAlgorithmName;
        NamedGroup = namedGroup;
        PacketProtectionAlgorithm = packetProtectionAlgorithm;
    }

    /// <summary>
    /// Gets the supported cipher suite.
    /// </summary>
    public QuicTlsCipherSuite CipherSuite { get; }

    /// <summary>
    /// Gets the transcript hash algorithm bound to the supported suite.
    /// </summary>
    public QuicTlsTranscriptHashAlgorithm TranscriptHashAlgorithm { get; }

    /// <summary>
    /// Gets the managed hash algorithm used for the transcript and Finished MAC.
    /// </summary>
    public HashAlgorithmName TranscriptHashAlgorithmName { get; }

    /// <summary>
    /// Gets the supported named group for the client-role key share.
    /// </summary>
    public QuicTlsNamedGroup NamedGroup { get; }

    /// <summary>
    /// Gets the AEAD algorithm used for handshake packet protection in this slice.
    /// </summary>
    public QuicAeadAlgorithm PacketProtectionAlgorithm { get; }

    /// <summary>
    /// Gets a short human-readable description of the supported subset.
    /// </summary>
    public static ReadOnlySpan<byte> SupportedSubsetDescriptionBytes => SupportedSubsetDescription;

    /// <summary>
    /// Tries to map a supported cipher suite to the permanent client-role TLS profile.
    /// </summary>
    public static bool TryGet(QuicTlsCipherSuite cipherSuite, out QuicTlsCipherSuiteProfile profile)
    {
        if (cipherSuite == QuicTlsCipherSuite.TlsAes128GcmSha256)
        {
            profile = new QuicTlsCipherSuiteProfile(
                QuicTlsCipherSuite.TlsAes128GcmSha256,
                QuicTlsTranscriptHashAlgorithm.Sha256,
                HashAlgorithmName.SHA256,
                QuicTlsNamedGroup.Secp256r1,
                QuicAeadAlgorithm.Aes128Gcm);
            return true;
        }

        profile = default;
        return false;
    }
}
