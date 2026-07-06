// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S19P6_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P6-0002")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_CryptoFrame_CarriesHandshakeBytesInCryptoFramePayloads()
    {
        foreach (CryptoFrameCase testCase in FrameCases())
        {
            QuicCryptoFrame frame = AssertCryptoFrameRoundTrip(testCase);

            Assert.Equal(testCase.Offset, frame.Offset);
            Assert.True(testCase.CryptoData.AsSpan().SequenceEqual(frame.CryptoData));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P6-0003")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_CryptoFrame_DoesNotCarryStreamIdentifiers()
    {
        foreach (byte streamFrameType in new byte[] { 0x08, 0x09, 0x0A, 0x0F })
        {
            byte[] streamFrame = QuicStreamTestData.BuildStreamFrame(
                streamFrameType,
                streamId: 4,
                streamData: [0xAA, 0xBB],
                offset: 0);

            Assert.True(QuicStreamParser.TryParseStreamFrame(streamFrame, out _));
            QuicS19P6CryptoFrameTestSupport.AssertRejects(streamFrame);
        }

        foreach (CryptoFrameCase testCase in FrameCases())
        {
            byte[] encoded = BuildFrame(testCase);
            Assert.Equal(QuicS19P6CryptoFrameTestSupport.CryptoFrameType, encoded[0]);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P6-0005")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_CryptoFrame_OffsetIsVariableLengthInteger()
    {
        foreach (ulong offset in VarintCases())
        {
            CryptoFrameCase testCase = new(offset, offset == QuicVariableLengthInteger.MaxValue ? [] : [0x01, 0x02]);
            QuicCryptoFrame frame = AssertCryptoFrameRoundTrip(testCase);

            Assert.Equal(offset, frame.Offset);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P6-0006")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_CryptoFrame_LengthIsVariableLengthInteger()
    {
        foreach (int length in new[] { 0, 1, 2, 63, 64, 128 })
        {
            CryptoFrameCase testCase = new(Offset: 0, SequentialBytes(0x30, length));
            QuicCryptoFrame frame = AssertCryptoFrameRoundTrip(testCase);

            Assert.Equal(length, frame.CryptoData.Length);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P6-0008")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_CryptoFrame_OffsetMapsDataPositionInCryptoStream()
    {
        foreach (CryptoFrameCase testCase in FrameCases())
        {
            QuicCryptoFrame frame = AssertCryptoFrameRoundTrip(testCase);

            Assert.Equal(testCase.Offset, frame.Offset);
            Assert.Equal(testCase.CryptoData.Length, frame.CryptoData.Length);
        }

        byte[] overflowingFrame = QuicS19P6CryptoFrameTestSupport.BuildCryptoFrameWithDeclaredLength(
            QuicVariableLengthInteger.MaxValue,
            declaredLength: 1,
            cryptoData: [0xAA]);
        QuicS19P6CryptoFrameTestSupport.AssertRejects(overflowingFrame);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P6-0009")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_CryptoFrame_LengthControlsConsumedCryptoData()
    {
        foreach (int declaredLength in new[] { 0, 1, 2, 4 })
        {
            byte[] encoded = QuicS19P6CryptoFrameTestSupport.BuildCryptoFrameWithDeclaredLength(
                offset: 0,
                (ulong)declaredLength,
                cryptoData: [0xA0, 0xA1, 0xA2, 0xA3, 0x00]);

            Assert.True(QuicFrameCodec.TryParseCryptoFrame(encoded, out QuicCryptoFrame frame, out int bytesConsumed));
            Assert.Equal(declaredLength, frame.CryptoData.Length);
            Assert.Equal(encoded.Length - (5 - declaredLength), bytesConsumed);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P6-0010")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_CryptoFrame_OffsetPlusLengthMustNotExceedCryptoStreamLimit()
    {
        foreach ((ulong offset, byte[] cryptoData) in new[]
        {
            (0UL, Array.Empty<byte>()),
            (QuicVariableLengthInteger.MaxValue, Array.Empty<byte>()),
            (QuicVariableLengthInteger.MaxValue - 1, new byte[] { 0xAA }),
        })
        {
            AssertCryptoFrameRoundTrip(new CryptoFrameCase(offset, cryptoData));
        }

        foreach ((ulong offset, byte[] cryptoData) in new[]
        {
            (QuicVariableLengthInteger.MaxValue, new byte[] { 0xAA }),
            (QuicVariableLengthInteger.MaxValue - 1, new byte[] { 0xAA, 0xBB }),
        })
        {
            byte[] encoded = QuicS19P6CryptoFrameTestSupport.BuildCryptoFrameWithDeclaredLength(
                offset,
                (ulong)cryptoData.Length,
                cryptoData);
            QuicS19P6CryptoFrameTestSupport.AssertRejects(encoded);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P6-0012")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_CryptoFrame_CarriesSingleEncryptionLevelStreamDataWithoutStreamId()
    {
        foreach (CryptoFrameCase testCase in FrameCases())
        {
            byte[] encoded = BuildFrame(testCase);

            Assert.Equal(QuicS19P6CryptoFrameTestSupport.CryptoFrameType, encoded[0]);
            Assert.DoesNotContain(encoded, value => value == 0x08 || value == 0x0F);

            QuicCryptoFrame frame = AssertCryptoFrameRoundTrip(testCase);
            Assert.Equal(testCase.Offset, frame.Offset);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P6-0013")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_CryptoFrame_TypeDoesNotCarryStreamFinBit()
    {
        foreach (CryptoFrameCase testCase in FrameCases())
        {
            byte[] encoded = BuildFrame(testCase);

            Assert.Equal((byte)0x06, encoded[0]);
            Assert.Equal(0, encoded[0] & 0x01);
            AssertCryptoFrameRoundTrip(testCase);
        }

        foreach (byte streamFrameTypeWithFin in new byte[] { 0x09, 0x0B, 0x0D, 0x0F })
        {
            byte[] streamFrame = QuicStreamTestData.BuildStreamFrame(
                streamFrameTypeWithFin,
                streamId: 0,
                streamData: [0xAA],
                offset: 0);

            QuicS19P6CryptoFrameTestSupport.AssertRejects(streamFrame);
        }
    }

    private static QuicCryptoFrame AssertCryptoFrameRoundTrip(CryptoFrameCase testCase)
    {
        byte[] encoded = BuildFrame(testCase);
        Assert.True(QuicFrameCodec.TryParseCryptoFrame(encoded, out QuicCryptoFrame parsed, out int bytesConsumed));
        Assert.Equal(encoded.Length, bytesConsumed);
        Assert.Equal(testCase.Offset, parsed.Offset);
        Assert.True(testCase.CryptoData.AsSpan().SequenceEqual(parsed.CryptoData));

        byte[] destination = new byte[encoded.Length];
        Assert.True(QuicFrameCodec.TryFormatCryptoFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination));
        return parsed;
    }

    private static IEnumerable<CryptoFrameCase> FrameCases()
    {
        yield return new CryptoFrameCase(0, []);
        yield return new CryptoFrameCase(1, [0x01]);
        yield return new CryptoFrameCase(63, SequentialBytes(0x10, 2));
        yield return new CryptoFrameCase(64, SequentialBytes(0x20, 63));
        yield return new CryptoFrameCase(16_384, SequentialBytes(0x30, 64));
        yield return new CryptoFrameCase(QuicVariableLengthInteger.MaxValue, []);
    }

    private static ulong[] VarintCases()
    {
        return [0, 1, 63, 64, 16_383, 16_384, QuicVariableLengthInteger.MaxValue];
    }

    private static byte[] BuildFrame(CryptoFrameCase testCase)
    {
        return QuicFrameTestData.BuildCryptoFrame(new QuicCryptoFrame(testCase.Offset, testCase.CryptoData));
    }

    private static byte[] SequentialBytes(byte seed, int length)
    {
        byte[] bytes = new byte[length];
        for (int index = 0; index < bytes.Length; index++)
        {
            bytes[index] = unchecked((byte)(seed + index));
        }

        return bytes;
    }

    private readonly record struct CryptoFrameCase(ulong Offset, byte[] CryptoData);
}
