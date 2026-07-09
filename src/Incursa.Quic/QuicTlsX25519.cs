// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers.Binary;
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

        FieldElement x1 = FieldElement.Decode(encodedU);
        FieldElement x2 = FieldElement.One;
        FieldElement z2 = FieldElement.Zero;
        FieldElement x3 = x1;
        FieldElement z3 = FieldElement.One;
        int swap = 0;

        for (int bitIndex = 254; bitIndex >= 0; bitIndex--)
        {
            int bit = (clampedScalar[bitIndex >> 3] >> (bitIndex & 7)) & 1;
            swap ^= bit;
            ConditionalSwap(swap, ref x2, ref x3);
            ConditionalSwap(swap, ref z2, ref z3);
            swap = bit;

            FieldElement a = x2 + z2;
            FieldElement aa = a.Square();
            FieldElement b = x2 - z2;
            FieldElement bb = b.Square();
            FieldElement e = aa - bb;
            FieldElement c = x3 + z3;
            FieldElement d = x3 - z3;
            FieldElement da = d * a;
            FieldElement cb = c * b;
            FieldElement daPlusCb = da + cb;
            FieldElement daMinusCb = da - cb;

            x3 = daPlusCb.Square();
            z3 = x1 * daMinusCb.Square();
            x2 = aa * bb;
            z2 = e * (aa + e.MultiplyBy121665());
        }

        ConditionalSwap(swap, ref x2, ref x3);
        ConditionalSwap(swap, ref z2, ref z3);

        FieldElement result = x2 * z2.Invert();
        result.Encode(output[..KeyLength]);
        return true;
    }

    private static void ClampScalar(Span<byte> scalar)
    {
        scalar[0] &= ClearLowScalarBitsMask;
        scalar[FinalByteIndex] &= ClearHighUCoordinateBitMask;
        scalar[FinalByteIndex] |= SetScalarSecondHighestBitMask;
    }

    private static void ConditionalSwap(int swap, ref FieldElement left, ref FieldElement right)
    {
        FieldElement.ConditionalSwapValues(swap, ref left, ref right);
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

    private struct FieldElement
    {
        private const int LimbBitCount = 51;
        private const int InversionExponentBitLength = 255;
        private const int PrimeMinusTwoClearBit2 = 2;
        private const int PrimeMinusTwoClearBit4 = 4;
        private const int DoubleModulusPadding = 2;
        private const int CurveA24 = 121665;
        private const int CarryFoldMultiplier = 19;
        private const int BitsPerByteShift = 3;
        private const int BitsPerByteMask = 7;
        private const ulong Low51Bits = (1UL << LimbBitCount) - 1;
        private const ulong PrimeLimb0 = Low51Bits - (CarryFoldMultiplier - 1);

        private ulong l0;
        private ulong l1;
        private ulong l2;
        private ulong l3;
        private ulong l4;

        private FieldElement(ulong l0, ulong l1, ulong l2, ulong l3, ulong l4)
        {
            this.l0 = l0;
            this.l1 = l1;
            this.l2 = l2;
            this.l3 = l3;
            this.l4 = l4;
        }

        internal static FieldElement Zero => default;

        internal static FieldElement One => new(1, 0, 0, 0, 0);

        internal static FieldElement Decode(ReadOnlySpan<byte> value)
        {
            ulong h0 = BinaryPrimitives.ReadUInt64LittleEndian(value[..8]) & Low51Bits;
            ulong h1 = (BinaryPrimitives.ReadUInt64LittleEndian(value.Slice(6, 8)) >> 3) & Low51Bits;
            ulong h2 = (BinaryPrimitives.ReadUInt64LittleEndian(value.Slice(12, 8)) >> 6) & Low51Bits;
            ulong h3 = (BinaryPrimitives.ReadUInt64LittleEndian(value.Slice(19, 8)) >> 1) & Low51Bits;
            ulong h4 = (BinaryPrimitives.ReadUInt64LittleEndian(value.Slice(24, 8)) >> 12) & Low51Bits;
            return new FieldElement(h0, h1, h2, h3, h4);
        }

        internal void Encode(Span<byte> destination)
        {
            FieldElement reduced = Normalize();
            destination.Clear();
            WriteLimb(destination, reduced.l0, bitOffset: 0);
            WriteLimb(destination, reduced.l1, bitOffset: 51);
            WriteLimb(destination, reduced.l2, bitOffset: 102);
            WriteLimb(destination, reduced.l3, bitOffset: 153);
            WriteLimb(destination, reduced.l4, bitOffset: 204);
        }

        internal static void ConditionalSwapValues(int swap, ref FieldElement left, ref FieldElement right)
        {
            ulong mask = 0UL - (ulong)(swap & 1);
            SwapLimbs(ref left.l0, ref right.l0, mask);
            SwapLimbs(ref left.l1, ref right.l1, mask);
            SwapLimbs(ref left.l2, ref right.l2, mask);
            SwapLimbs(ref left.l3, ref right.l3, mask);
            SwapLimbs(ref left.l4, ref right.l4, mask);
        }

        public static FieldElement operator +(FieldElement left, FieldElement right)
            => Reduce(
                (UInt128)left.l0 + right.l0,
                (UInt128)left.l1 + right.l1,
                (UInt128)left.l2 + right.l2,
                (UInt128)left.l3 + right.l3,
                (UInt128)left.l4 + right.l4);

        public static FieldElement operator -(FieldElement left, FieldElement right)
            => Reduce(
                (UInt128)left.l0 + (DoubleModulusPadding * PrimeLimb0) - right.l0,
                (UInt128)left.l1 + (DoubleModulusPadding * Low51Bits) - right.l1,
                (UInt128)left.l2 + (DoubleModulusPadding * Low51Bits) - right.l2,
                (UInt128)left.l3 + (DoubleModulusPadding * Low51Bits) - right.l3,
                (UInt128)left.l4 + (DoubleModulusPadding * Low51Bits) - right.l4);

        public static FieldElement operator *(FieldElement left, FieldElement right)
        {
            UInt128 h0 = ((UInt128)left.l0 * right.l0)
                + (CarryFoldMultiplier * (((UInt128)left.l1 * right.l4)
                + ((UInt128)left.l2 * right.l3)
                + ((UInt128)left.l3 * right.l2)
                + ((UInt128)left.l4 * right.l1)));
            UInt128 h1 = ((UInt128)left.l0 * right.l1)
                + ((UInt128)left.l1 * right.l0)
                + (CarryFoldMultiplier * (((UInt128)left.l2 * right.l4)
                + ((UInt128)left.l3 * right.l3)
                + ((UInt128)left.l4 * right.l2)));
            UInt128 h2 = ((UInt128)left.l0 * right.l2)
                + ((UInt128)left.l1 * right.l1)
                + ((UInt128)left.l2 * right.l0)
                + (CarryFoldMultiplier * (((UInt128)left.l3 * right.l4)
                + ((UInt128)left.l4 * right.l3)));
            UInt128 h3 = ((UInt128)left.l0 * right.l3)
                + ((UInt128)left.l1 * right.l2)
                + ((UInt128)left.l2 * right.l1)
                + ((UInt128)left.l3 * right.l0)
                + (CarryFoldMultiplier * ((UInt128)left.l4 * right.l4));
            UInt128 h4 = ((UInt128)left.l0 * right.l4)
                + ((UInt128)left.l1 * right.l3)
                + ((UInt128)left.l2 * right.l2)
                + ((UInt128)left.l3 * right.l1)
                + ((UInt128)left.l4 * right.l0);

            return Reduce(h0, h1, h2, h3, h4);
        }

        internal FieldElement Square()
            => this * this;

        internal FieldElement MultiplyBy121665()
            => Reduce(
                (UInt128)l0 * CurveA24,
                (UInt128)l1 * CurveA24,
                (UInt128)l2 * CurveA24,
                (UInt128)l3 * CurveA24,
                (UInt128)l4 * CurveA24);

        internal FieldElement Invert()
        {
            FieldElement result = One;
            for (int bitIndex = 254; bitIndex >= 0; bitIndex--)
            {
                result = result.Square();
                if (IsPrimeMinusTwoBitSet(bitIndex))
                {
                    result *= this;
                }
            }

            return result;
        }

        private FieldElement Normalize()
        {
            FieldElement reduced = Reduce(l0, l1, l2, l3, l4);
            if (!reduced.IsGreaterThanOrEqualToPrime())
            {
                return reduced;
            }

            return new FieldElement(
                reduced.l0 - PrimeLimb0,
                reduced.l1 - Low51Bits,
                reduced.l2 - Low51Bits,
                reduced.l3 - Low51Bits,
                reduced.l4 - Low51Bits);
        }

        private bool IsGreaterThanOrEqualToPrime()
            => l4 == Low51Bits
                && l3 == Low51Bits
                && l2 == Low51Bits
                && l1 == Low51Bits
                && l0 >= PrimeLimb0;

        private static FieldElement Reduce(UInt128 h0, UInt128 h1, UInt128 h2, UInt128 h3, UInt128 h4)
        {
            Carry(ref h0, ref h1);
            Carry(ref h1, ref h2);
            Carry(ref h2, ref h3);
            Carry(ref h3, ref h4);

            UInt128 carry4 = h4 >> LimbBitCount;
            h4 &= Low51Bits;
            h0 += carry4 * CarryFoldMultiplier;
            Carry(ref h0, ref h1);

            return new FieldElement((ulong)h0, (ulong)h1, (ulong)h2, (ulong)h3, (ulong)h4);
        }

        private static void Carry(ref UInt128 current, ref UInt128 next)
        {
            UInt128 carry = current >> LimbBitCount;
            current &= Low51Bits;
            next += carry;
        }

        private static bool IsPrimeMinusTwoBitSet(int bitIndex)
        {
            if (bitIndex == PrimeMinusTwoClearBit2 || bitIndex == PrimeMinusTwoClearBit4)
            {
                return false;
            }

            return bitIndex < InversionExponentBitLength;
        }

        private static void SwapLimbs(ref ulong left, ref ulong right, ulong mask)
        {
            ulong value = mask & (left ^ right);
            left ^= value;
            right ^= value;
        }

        private static void WriteLimb(Span<byte> destination, ulong limb, int bitOffset)
        {
            for (int bitIndex = 0; bitIndex < LimbBitCount; bitIndex++)
            {
                if (((limb >> bitIndex) & 1UL) == 0)
                {
                    continue;
                }

                int destinationBit = bitOffset + bitIndex;
                destination[destinationBit >> BitsPerByteShift] |= (byte)(1 << (destinationBit & BitsPerByteMask));
            }
        }
    }
}
