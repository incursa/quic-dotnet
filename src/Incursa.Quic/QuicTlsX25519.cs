// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Numerics;
using System.Security.Cryptography;

namespace Incursa.Quic;

// CONTEXT: The routine is intentionally self-contained so the repo can derive X25519 key pairs and
// shared secrets without introducing a platform-specific ECDH dependency.
// SEE: QuicTlsTransport
internal static class QuicTlsX25519
{
    internal const int KeyLength = 32;

    private const int FinalByteIndex = KeyLength - 1;
    private const byte ClearLowScalarBitsMask = 248;
    private const byte ClearHighUCoordinateBitMask = 127;
    private const byte SetScalarSecondHighestBitMask = 64;

    private static readonly BigInteger Prime = (BigInteger.One << 255) - 19;
    private static readonly BigInteger A24 = 121665;
    private static readonly byte[] BasePoint =
    [
        0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    internal static bool TryCreateKeyPair(out byte[] privateKey, out byte[] publicKey)
    {
        privateKey = new byte[KeyLength];
        publicKey = new byte[KeyLength];
        RandomNumberGenerator.Fill(privateKey);
        return TryGetPublicKey(privateKey, publicKey);
    }

    internal static bool TryGetPublicKey(ReadOnlySpan<byte> privateKey, Span<byte> publicKey)
        => TryScalarMult(privateKey, BasePoint, publicKey);

    internal static bool TryDeriveSharedSecret(
        ReadOnlySpan<byte> privateKey,
        ReadOnlySpan<byte> peerPublicKey,
        Span<byte> sharedSecret)
    {
        if (!TryScalarMult(privateKey, peerPublicKey, sharedSecret))
        {
            return false;
        }

        return !IsAllZero(sharedSecret);
    }

    private static bool TryScalarMult(
        ReadOnlySpan<byte> scalar,
        ReadOnlySpan<byte> uCoordinate,
        Span<byte> output)
    {
        if (scalar.Length != KeyLength
            || uCoordinate.Length != KeyLength
            || output.Length < KeyLength)
        {
            return false;
        }

        Span<byte> clampedScalar = stackalloc byte[KeyLength];
        scalar.CopyTo(clampedScalar);
        ClampScalar(clampedScalar);

        Span<byte> encodedU = stackalloc byte[KeyLength];
        uCoordinate.CopyTo(encodedU);
        encodedU[FinalByteIndex] &= ClearHighUCoordinateBitMask;

        BigInteger x1 = DecodeLittleEndian(encodedU);
        BigInteger x2 = BigInteger.One;
        BigInteger z2 = BigInteger.Zero;
        BigInteger x3 = x1;
        BigInteger z3 = BigInteger.One;
        int swap = 0;

        for (int bitIndex = 254; bitIndex >= 0; bitIndex--)
        {
            int bit = (clampedScalar[bitIndex >> 3] >> (bitIndex & 7)) & 1;
            swap ^= bit;
            ConditionalSwap(swap, ref x2, ref x3);
            ConditionalSwap(swap, ref z2, ref z3);
            swap = bit;

            BigInteger a = Mod(x2 + z2);
            BigInteger aa = Mod(a * a);
            BigInteger b = Mod(x2 - z2);
            BigInteger bb = Mod(b * b);
            BigInteger e = Mod(aa - bb);
            BigInteger c = Mod(x3 + z3);
            BigInteger d = Mod(x3 - z3);
            BigInteger da = Mod(d * a);
            BigInteger cb = Mod(c * b);
            BigInteger daPlusCb = Mod(da + cb);
            BigInteger daMinusCb = Mod(da - cb);

            x3 = Mod(daPlusCb * daPlusCb);
            z3 = Mod(x1 * daMinusCb * daMinusCb);
            x2 = Mod(aa * bb);
            z2 = Mod(e * (aa + (A24 * e)));
        }

        ConditionalSwap(swap, ref x2, ref x3);
        ConditionalSwap(swap, ref z2, ref z3);

        BigInteger result = Mod(x2 * BigInteger.ModPow(z2, Prime - 2, Prime));
        EncodeLittleEndian(result, output[..KeyLength]);
        return true;
    }

    private static void ClampScalar(Span<byte> scalar)
    {
        scalar[0] &= ClearLowScalarBitsMask;
        scalar[FinalByteIndex] &= ClearHighUCoordinateBitMask;
        scalar[FinalByteIndex] |= SetScalarSecondHighestBitMask;
    }

    private static BigInteger DecodeLittleEndian(ReadOnlySpan<byte> value)
        => new(value, isUnsigned: true, isBigEndian: false);

    private static void EncodeLittleEndian(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        _ = value.TryWriteBytes(destination, out _, isUnsigned: true, isBigEndian: false);
    }

    private static BigInteger Mod(BigInteger value)
    {
        value %= Prime;
        return value.Sign < 0 ? value + Prime : value;
    }

    private static void ConditionalSwap(int swap, ref BigInteger left, ref BigInteger right)
    {
        if (swap == 0)
        {
            return;
        }

        (left, right) = (right, left);
    }

    private static bool IsAllZero(ReadOnlySpan<byte> value)
    {
        byte accumulator = 0;
        foreach (byte item in value)
        {
            accumulator |= item;
        }

        return accumulator == 0;
    }
}
