// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers.Binary;
using System.Security.Cryptography;

#pragma warning disable S109

namespace Incursa.Quic;

// CONTEXT: This context keeps algorithm-specific AEAD/header-protection primitives separate and
// disposable because the packet-protection hot path needs direct access to the chosen cipher
// without rebuilding crypto objects per packet.
// SEE: QuicTlsPacketProtectionMaterial
/// <summary>
/// Caches the reusable cryptographic primitives for a single packet-protection key set.
/// </summary>
internal sealed class QuicPacketProtectionCryptoContext : IDisposable
{
    private const int AuthenticationTagLength = QuicInitialPacketProtection.AuthenticationTagLength;
    private const int ChaCha20BlockByteLength = 64;
    private const int ChaCha20HeaderProtectionMaskLength = 5;
    private const int ChaCha20StateWordCount = 16;
    private const uint ChaCha20State0 = 0x61707865;
    private const uint ChaCha20State1 = 0x3320646e;
    private const uint ChaCha20State2 = 0x79622d32;
    private const uint ChaCha20State3 = 0x6b206574;

    private readonly QuicAeadAlgorithm algorithm;
    private readonly AesGcm? aeadGcm;
    private readonly AesCcm? aeadCcm;
    private readonly ChaCha20Poly1305? aeadChaCha20Poly1305;
    private readonly Aes? headerProtectionAes;
    private readonly ICryptoTransform? headerProtectionAesEncryptor;
    private readonly object? headerProtectionAesLock;
    private readonly byte[]? headerProtectionSampleBuffer;
    private readonly byte[]? headerProtectionMaskBuffer;
    private readonly byte[] headerProtectionKey;
    private bool disposed;

    internal QuicPacketProtectionCryptoContext(
        QuicAeadAlgorithm algorithm,
        byte[] aeadKey,
        byte[] headerProtectionKey)
    {
        this.algorithm = algorithm;
        this.headerProtectionKey = headerProtectionKey.ToArray();

        switch (algorithm)
        {
            case QuicAeadAlgorithm.Aes128Gcm:
            case QuicAeadAlgorithm.Aes256Gcm:
                aeadGcm = new AesGcm(aeadKey, AuthenticationTagLength);
                headerProtectionAes = CreateAesHeaderProtectionContext(headerProtectionKey);
                headerProtectionAesEncryptor = headerProtectionAes.CreateEncryptor();
                headerProtectionAesLock = new object();
                headerProtectionSampleBuffer = new byte[QuicInitialPacketProtection.HeaderProtectionSampleLength];
                headerProtectionMaskBuffer = new byte[QuicInitialPacketProtection.HeaderProtectionSampleLength];
                break;

            case QuicAeadAlgorithm.Aes128Ccm:
                aeadCcm = new AesCcm(aeadKey);
                headerProtectionAes = CreateAesHeaderProtectionContext(headerProtectionKey);
                headerProtectionAesEncryptor = headerProtectionAes.CreateEncryptor();
                headerProtectionAesLock = new object();
                headerProtectionSampleBuffer = new byte[QuicInitialPacketProtection.HeaderProtectionSampleLength];
                headerProtectionMaskBuffer = new byte[QuicInitialPacketProtection.HeaderProtectionSampleLength];
                break;

            case QuicAeadAlgorithm.Chacha20Poly1305:
                if (!ChaCha20Poly1305.IsSupported)
                {
                    throw new PlatformNotSupportedException("ChaCha20-Poly1305 is not supported on this platform.");
                }

                aeadChaCha20Poly1305 = new ChaCha20Poly1305(aeadKey);
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
            QuicMetrics.RecordAeadOpenFailure(algorithm);
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
            switch (algorithm)
            {
                case QuicAeadAlgorithm.Aes128Gcm:
                case QuicAeadAlgorithm.Aes256Gcm:
                case QuicAeadAlgorithm.Aes128Ccm:
                    return TryGenerateAesHeaderProtectionMask(sample, destination);

                case QuicAeadAlgorithm.Chacha20Poly1305:
                    return TryGenerateChaCha20HeaderProtectionMask(sample, destination);

                default:
                    return false;
            }
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private static Aes CreateAesHeaderProtectionContext(byte[] headerProtectionKey)
    {
        Aes headerProtectionAes = Aes.Create();
        headerProtectionAes.Key = headerProtectionKey;
        headerProtectionAes.Mode = CipherMode.ECB;
        headerProtectionAes.Padding = PaddingMode.None;
        return headerProtectionAes;
    }

    private bool TryGenerateAesHeaderProtectionMask(ReadOnlySpan<byte> sample, Span<byte> destination)
    {
        lock (headerProtectionAesLock!)
        {
            Span<byte> sampleBuffer = headerProtectionSampleBuffer!;
            Span<byte> maskBuffer = headerProtectionMaskBuffer!;
            sample[..QuicInitialPacketProtection.HeaderProtectionSampleLength].CopyTo(sampleBuffer);
            int bytesWritten = headerProtectionAesEncryptor!.TransformBlock(
                headerProtectionSampleBuffer!,
                0,
                QuicInitialPacketProtection.HeaderProtectionSampleLength,
                headerProtectionMaskBuffer!,
                0);
            if (bytesWritten != QuicInitialPacketProtection.HeaderProtectionSampleLength)
            {
                return false;
            }

            maskBuffer[..QuicInitialPacketProtection.HeaderProtectionSampleLength].CopyTo(destination);
            return true;
        }
    }

    private bool TryGenerateChaCha20HeaderProtectionMask(ReadOnlySpan<byte> sample, Span<byte> destination)
    {
        Span<byte> block = stackalloc byte[ChaCha20BlockByteLength];
        if (!TryChaCha20Block(
            headerProtectionKey,
            BinaryPrimitives.ReadUInt32LittleEndian(sample[..sizeof(uint)]),
            sample.Slice(sizeof(uint), 12),
            block))
        {
            return false;
        }

        destination[..QuicInitialPacketProtection.HeaderProtectionSampleLength].Clear();
        block[..ChaCha20HeaderProtectionMaskLength].CopyTo(destination);
        return true;
    }

    private static bool TryChaCha20Block(
        ReadOnlySpan<byte> key,
        uint counter,
        ReadOnlySpan<byte> nonce,
        Span<byte> destination)
    {
        if (key.Length != 32
            || nonce.Length != 12
            || destination.Length < ChaCha20BlockByteLength)
        {
            return false;
        }

        Span<uint> state = stackalloc uint[ChaCha20StateWordCount];
        state[0] = ChaCha20State0;
        state[1] = ChaCha20State1;
        state[2] = ChaCha20State2;
        state[3] = ChaCha20State3;

        for (int index = 0; index < 8; index++)
        {
            state[4 + index] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(index * sizeof(uint), sizeof(uint)));
        }

        state[12] = counter;
        state[13] = BinaryPrimitives.ReadUInt32LittleEndian(nonce[..sizeof(uint)]);
        state[14] = BinaryPrimitives.ReadUInt32LittleEndian(nonce.Slice(sizeof(uint), sizeof(uint)));
        state[15] = BinaryPrimitives.ReadUInt32LittleEndian(nonce.Slice(sizeof(uint) * 2, sizeof(uint)));

        Span<uint> workingState = stackalloc uint[ChaCha20StateWordCount];
        state.CopyTo(workingState);

        for (int round = 0; round < 10; round++)
        {
            QuarterRound(ref workingState[0], ref workingState[4], ref workingState[8], ref workingState[12]);
            QuarterRound(ref workingState[1], ref workingState[5], ref workingState[9], ref workingState[13]);
            QuarterRound(ref workingState[2], ref workingState[6], ref workingState[10], ref workingState[14]);
            QuarterRound(ref workingState[3], ref workingState[7], ref workingState[11], ref workingState[15]);

            QuarterRound(ref workingState[0], ref workingState[5], ref workingState[10], ref workingState[15]);
            QuarterRound(ref workingState[1], ref workingState[6], ref workingState[11], ref workingState[12]);
            QuarterRound(ref workingState[2], ref workingState[7], ref workingState[8], ref workingState[13]);
            QuarterRound(ref workingState[3], ref workingState[4], ref workingState[9], ref workingState[14]);
        }

        for (int index = 0; index < ChaCha20StateWordCount; index++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(
                destination.Slice(index * sizeof(uint), sizeof(uint)),
                unchecked(workingState[index] + state[index]));
        }

        return true;
    }

    private static void QuarterRound(ref uint a, ref uint b, ref uint c, ref uint d)
    {
        a = unchecked(a + b);
        d = RotateLeft(d ^ a, 16);

        c = unchecked(c + d);
        b = RotateLeft(b ^ c, 12);

        a = unchecked(a + b);
        d = RotateLeft(d ^ a, 8);

        c = unchecked(c + d);
        b = RotateLeft(b ^ c, 7);
    }

    private static uint RotateLeft(uint value, int offset)
    {
        return (value << offset) | (value >> (32 - offset));
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
        headerProtectionAesEncryptor?.Dispose();
        headerProtectionAes?.Dispose();
        if (headerProtectionSampleBuffer is not null)
        {
            CryptographicOperations.ZeroMemory(headerProtectionSampleBuffer);
        }

        if (headerProtectionMaskBuffer is not null)
        {
            CryptographicOperations.ZeroMemory(headerProtectionMaskBuffer);
        }

        CryptographicOperations.ZeroMemory(headerProtectionKey);
    }
}

#pragma warning restore S109
