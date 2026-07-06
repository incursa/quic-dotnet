// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S16_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0905")]
    [Requirement("REQ-QUIC-RFC9000-0906")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_VarintLengthPrefixesAndRemainingBitsRoundTrip()
    {
        foreach ((ulong value, int encodedLength) in VarintCorpus())
        {
            byte[] encoded = QuicVarintTestData.EncodeWithLength(value, encodedLength);

            Assert.Equal(ExpectedLengthPrefix(encodedLength), encoded[0] & 0xC0);
            Assert.True(QuicVariableLengthInteger.TryParse(encoded, out ulong parsed, out int bytesConsumed));
            Assert.Equal(value, parsed);
            Assert.Equal(encodedLength, bytesConsumed);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0913")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_VarintParserAcceptsNonMinimalEncodings()
    {
        foreach ((ulong value, int encodedLength) in VarintCorpus())
        {
            if (QuicVarintTestData.EncodeMinimal(value).Length >= encodedLength)
            {
                continue;
            }

            byte[] encoded = QuicVarintTestData.EncodeWithLength(value, encodedLength);

            Assert.True(QuicVariableLengthInteger.TryParse(encoded, out ulong parsed, out int bytesConsumed));
            Assert.Equal(value, parsed);
            Assert.Equal(encodedLength, bytesConsumed);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0905")]
    [Requirement("REQ-QUIC-RFC9000-0913")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_VarintParserRejectsTruncatedLengthPromises()
    {
        foreach ((ulong value, int encodedLength) in VarintCorpus().Where(static testCase => testCase.encodedLength > 1))
        {
            byte[] encoded = QuicVarintTestData.EncodeWithLength(value, encodedLength);

            Assert.False(QuicVariableLengthInteger.TryParse(encoded[..^1], out _, out _));
        }
    }

    private static IEnumerable<(ulong value, int encodedLength)> VarintCorpus()
    {
        ulong[] edgeValues =
        [
            0,
            1,
            63,
            64,
            16_383,
            16_384,
            1_073_741_823,
            1_073_741_824,
            QuicVariableLengthInteger.MaxValue,
        ];

        foreach (ulong value in edgeValues)
        {
            foreach (int encodedLength in EncodableLengths(value))
            {
                yield return (value, encodedLength);
            }
        }

        Random random = new(0x1000_0016);
        for (int i = 0; i < 128; i++)
        {
            ulong value = ((ulong)random.Next() << 32) | (uint)random.Next();
            value &= QuicVariableLengthInteger.MaxValue;

            foreach (int encodedLength in EncodableLengths(value))
            {
                yield return (value, encodedLength);
            }
        }
    }

    private static IEnumerable<int> EncodableLengths(ulong value)
    {
        if (value <= 63)
        {
            yield return 1;
        }

        if (value <= 16_383)
        {
            yield return 2;
        }

        if (value <= 1_073_741_823)
        {
            yield return 4;
        }

        yield return 8;
    }

    private static int ExpectedLengthPrefix(int encodedLength)
    {
        return encodedLength switch
        {
            1 => 0x00,
            2 => 0x40,
            4 => 0x80,
            8 => 0xC0,
            _ => throw new ArgumentOutOfRangeException(nameof(encodedLength)),
        };
    }
}
