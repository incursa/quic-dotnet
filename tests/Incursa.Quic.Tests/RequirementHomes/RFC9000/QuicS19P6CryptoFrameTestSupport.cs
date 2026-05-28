// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

internal static class QuicS19P6CryptoFrameTestSupport
{
    internal const byte CryptoFrameType = 0x06;

    internal static byte[] BuildCryptoFrameWithEncodedType(int encodedTypeLength, ulong offset, ReadOnlySpan<byte> cryptoData)
    {
        return BuildCryptoFrameWithFields(
            QuicVarintTestData.EncodeWithLength(CryptoFrameType, encodedTypeLength),
            QuicVarintTestData.EncodeMinimal(offset),
            QuicVarintTestData.EncodeMinimal((ulong)cryptoData.Length),
            cryptoData);
    }

    internal static byte[] BuildCryptoFrameWithEncodedOffset(ulong offset, int encodedOffsetLength, ReadOnlySpan<byte> cryptoData)
    {
        return BuildCryptoFrameWithFields(
            [CryptoFrameType],
            QuicVarintTestData.EncodeWithLength(offset, encodedOffsetLength),
            QuicVarintTestData.EncodeMinimal((ulong)cryptoData.Length),
            cryptoData);
    }

    internal static byte[] BuildCryptoFrameWithEncodedLength(
        ulong offset,
        ulong declaredLength,
        int encodedLengthLength,
        ReadOnlySpan<byte> cryptoData)
    {
        return BuildCryptoFrameWithFields(
            [CryptoFrameType],
            QuicVarintTestData.EncodeMinimal(offset),
            QuicVarintTestData.EncodeWithLength(declaredLength, encodedLengthLength),
            cryptoData);
    }

    internal static byte[] BuildCryptoFrameWithDeclaredLength(
        ulong offset,
        ulong declaredLength,
        ReadOnlySpan<byte> cryptoData)
    {
        return BuildCryptoFrameWithFields(
            [CryptoFrameType],
            QuicVarintTestData.EncodeMinimal(offset),
            QuicVarintTestData.EncodeMinimal(declaredLength),
            cryptoData);
    }

    internal static byte[] BuildCryptoFrameWithFields(
        ReadOnlySpan<byte> typeBytes,
        ReadOnlySpan<byte> offsetBytes,
        ReadOnlySpan<byte> lengthBytes,
        ReadOnlySpan<byte> cryptoData)
    {
        byte[] frame = new byte[typeBytes.Length + offsetBytes.Length + lengthBytes.Length + cryptoData.Length];
        int index = 0;

        typeBytes.CopyTo(frame.AsSpan(index));
        index += typeBytes.Length;

        offsetBytes.CopyTo(frame.AsSpan(index));
        index += offsetBytes.Length;

        lengthBytes.CopyTo(frame.AsSpan(index));
        index += lengthBytes.Length;

        cryptoData.CopyTo(frame.AsSpan(index));
        return frame;
    }

    internal static void AssertParses(ReadOnlySpan<byte> frameBytes, ulong expectedOffset, ReadOnlySpan<byte> expectedCryptoData)
    {
        Assert.True(QuicFrameCodec.TryParseCryptoFrame(frameBytes, out QuicCryptoFrame frame, out int bytesConsumed));
        Assert.Equal(frameBytes.Length, bytesConsumed);
        Assert.Equal(expectedOffset, frame.Offset);
        Assert.True(expectedCryptoData.SequenceEqual(frame.CryptoData));
    }

    internal static void AssertRejects(ReadOnlySpan<byte> frameBytes)
    {
        Assert.False(QuicFrameCodec.TryParseCryptoFrame(frameBytes, out _, out _));
    }
}
