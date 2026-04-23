using System.Security.Cryptography;

namespace Incursa.Quic;

/// <summary>
/// Caches the reusable cryptographic primitives for a single packet-protection key set.
/// </summary>
internal sealed class QuicPacketProtectionCryptoContext : IDisposable
{
    private const int AuthenticationTagLength = QuicInitialPacketProtection.AuthenticationTagLength;

    private readonly QuicAeadAlgorithm algorithm;
    private readonly AesGcm? aeadGcm;
    private readonly AesCcm? aeadCcm;
    private readonly Aes headerProtectionAes;
    private bool disposed;

    internal QuicPacketProtectionCryptoContext(
        QuicAeadAlgorithm algorithm,
        byte[] aeadKey,
        byte[] headerProtectionKey)
    {
        this.algorithm = algorithm;

        switch (algorithm)
        {
            case QuicAeadAlgorithm.Aes128Gcm:
            case QuicAeadAlgorithm.Aes256Gcm:
                aeadGcm = new AesGcm(aeadKey, AuthenticationTagLength);
                break;

            case QuicAeadAlgorithm.Aes128Ccm:
                aeadCcm = new AesCcm(aeadKey);
                break;

            default:
                throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, null);
        }

        headerProtectionAes = Aes.Create();
        headerProtectionAes.Key = headerProtectionKey;
        headerProtectionAes.Mode = CipherMode.ECB;
        headerProtectionAes.Padding = PaddingMode.None;
    }

    ~QuicPacketProtectionCryptoContext()
    {
        DisposeCore();
    }

    public void Dispose()
    {
        DisposeCore();
        GC.SuppressFinalize(this);
    }

    internal bool TryEncryptPacketPayload(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext,
        Span<byte> tag,
        ReadOnlySpan<byte> associatedData)
    {
        if (disposed)
        {
            return false;
        }

        try
        {
            switch (algorithm)
            {
                case QuicAeadAlgorithm.Aes128Gcm:
                case QuicAeadAlgorithm.Aes256Gcm:
                    aeadGcm!.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
                    return true;

                case QuicAeadAlgorithm.Aes128Ccm:
                    aeadCcm!.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
                    return true;

                default:
                    return false;
            }
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    internal bool TryDecryptPacketPayload(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        Span<byte> plaintext,
        ReadOnlySpan<byte> associatedData)
    {
        if (disposed)
        {
            return false;
        }

        try
        {
            switch (algorithm)
            {
                case QuicAeadAlgorithm.Aes128Gcm:
                case QuicAeadAlgorithm.Aes256Gcm:
                    aeadGcm!.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
                    return true;

                case QuicAeadAlgorithm.Aes128Ccm:
                    aeadCcm!.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
                    return true;

                default:
                    return false;
            }
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    internal bool TryGenerateHeaderProtectionMask(
        ReadOnlySpan<byte> sample,
        Span<byte> destination)
    {
        if (disposed
            || sample.Length < QuicInitialPacketProtection.HeaderProtectionSampleLength
            || destination.Length < QuicInitialPacketProtection.HeaderProtectionSampleLength)
        {
            return false;
        }

        try
        {
            return headerProtectionAes.EncryptEcb(
                sample[..QuicInitialPacketProtection.HeaderProtectionSampleLength],
                destination[..QuicInitialPacketProtection.HeaderProtectionSampleLength],
                PaddingMode.None)
                == QuicInitialPacketProtection.HeaderProtectionSampleLength;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private void DisposeCore()
    {
        if (disposed)
        {
            return;
        }

        disposed = true;
        aeadGcm?.Dispose();
        aeadCcm?.Dispose();
        headerProtectionAes.Dispose();
    }
}
