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
    private readonly ChaCha20Poly1305? aeadChaCha20Poly1305;
    private readonly Aes? headerProtectionAes;
    private readonly byte[]? headerProtectionChaCha20Key;
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
                headerProtectionAes = Aes.Create();
                headerProtectionAes.Key = headerProtectionKey;
                headerProtectionAes.Mode = CipherMode.ECB;
                headerProtectionAes.Padding = PaddingMode.None;
                break;

            case QuicAeadAlgorithm.Aes128Ccm:
                aeadCcm = new AesCcm(aeadKey);
                headerProtectionAes = Aes.Create();
                headerProtectionAes.Key = headerProtectionKey;
                headerProtectionAes.Mode = CipherMode.ECB;
                headerProtectionAes.Padding = PaddingMode.None;
                break;

            case QuicAeadAlgorithm.Chacha20Poly1305:
                aeadChaCha20Poly1305 = new ChaCha20Poly1305(aeadKey);
                headerProtectionChaCha20Key = headerProtectionKey.ToArray();
                break;

            default:
                throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, null);
        }
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

                case QuicAeadAlgorithm.Chacha20Poly1305:
                    aeadChaCha20Poly1305!.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
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

                case QuicAeadAlgorithm.Chacha20Poly1305:
                    aeadChaCha20Poly1305!.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
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
            return algorithm switch
            {
                QuicAeadAlgorithm.Aes128Gcm or QuicAeadAlgorithm.Aes256Gcm or QuicAeadAlgorithm.Aes128Ccm => headerProtectionAes!.EncryptEcb(
                    sample[..QuicInitialPacketProtection.HeaderProtectionSampleLength],
                    destination[..QuicInitialPacketProtection.HeaderProtectionSampleLength],
                    PaddingMode.None) == QuicInitialPacketProtection.HeaderProtectionSampleLength,
                QuicAeadAlgorithm.Chacha20Poly1305 => headerProtectionChaCha20Key is not null
                    && QuicChaCha20.TryGenerateHeaderProtectionMask(
                        headerProtectionChaCha20Key,
                        sample[..QuicInitialPacketProtection.HeaderProtectionSampleLength],
                        destination[..QuicInitialPacketProtection.HeaderProtectionSampleLength]),
                _ => false,
            };
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
        aeadChaCha20Poly1305?.Dispose();
        headerProtectionAes?.Dispose();
    }
}
