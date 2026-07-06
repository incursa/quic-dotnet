// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S17P2P5_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P5-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RetryPacket_UsesLongHeaderTypeThree()
    {
        foreach (RetryPacketCase testCase in RetryPacketCases())
        {
            QuicLongHeaderPacket header = AssertRetryPacketRoundTrip(testCase);

            Assert.Equal(QuicHeaderForm.Long, header.HeaderForm);
            Assert.Equal((byte)QuicLongPacketTypeBits.Retry, header.LongPacketTypeBits);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P5-0003")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RetryHeaderFormBit_IsAlwaysLongHeader()
    {
        foreach (RetryPacketCase testCase in RetryPacketCases())
        {
            byte[] packet = BuildRetryPacket(testCase);

            Assert.True(QuicPacketParser.TryClassifyHeaderForm(packet, out QuicHeaderForm headerForm));
            Assert.Equal(QuicHeaderForm.Long, headerForm);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P5-0004")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RetryFixedBit_IsSetAcrossUnusedBitsAndCidLengths()
    {
        foreach (RetryPacketCase testCase in RetryPacketCases())
        {
            QuicLongHeaderPacket header = AssertRetryPacketRoundTrip(testCase);

            Assert.True(header.FixedBit);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P5-0005")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RetryLongPacketTypeBits_AreTypeThree()
    {
        foreach (RetryPacketCase testCase in RetryPacketCases())
        {
            QuicLongHeaderPacket header = AssertRetryPacketRoundTrip(testCase);

            Assert.Equal((byte)0x03, header.LongPacketTypeBits);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P5-0006")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RetryUnusedBits_AreFourBitsWideAndPreservedForValidation()
    {
        foreach (RetryPacketCase testCase in RetryPacketCases())
        {
            QuicLongHeaderPacket header = AssertRetryPacketRoundTrip(testCase);

            Assert.InRange(header.TypeSpecificBits, (byte)0, (byte)15);
            Assert.Equal(testCase.UnusedBits, header.TypeSpecificBits);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P5-0007")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RetryVersionField_IsThirtyTwoBitsAndPreserved()
    {
        foreach (uint version in new[] { QuicVersionNegotiation.Version1, QuicVersionNegotiation.Version2 })
        {
            byte[] packet = QuicRetryPacketRequirementTestData.BuildRetryPacket(
                version: version,
                destinationConnectionId: SequentialBytes(0xD0, 8),
                sourceConnectionId: SequentialBytes(0x50, 8),
                retryToken: SequentialBytes(0x80, 4),
                retryIntegrityTag: SequentialBytes(0xA0, QuicRetryIntegrity.RetryIntegrityTagLength));

            Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
            Assert.Equal(version, header.Version);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P5-0008")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RetryDestinationConnectionIdLength_IsEightBits()
    {
        foreach (RetryPacketCase testCase in RetryPacketCases())
        {
            QuicLongHeaderPacket header = AssertRetryPacketRoundTrip(testCase);

            Assert.Equal(testCase.DestinationConnectionIdLength, header.DestinationConnectionIdLength);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P5-0009")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RetryDestinationConnectionId_IsZeroToTwentyBytes()
    {
        foreach (RetryPacketCase testCase in RetryPacketCases())
        {
            QuicLongHeaderPacket header = AssertRetryPacketRoundTrip(testCase);

            Assert.InRange(header.DestinationConnectionId.Length, 0, 20);
            Assert.Equal(testCase.DestinationConnectionIdLength, header.DestinationConnectionId.Length);
            Assert.True(SequentialBytes(0xD0, testCase.DestinationConnectionIdLength).AsSpan()
                .SequenceEqual(header.DestinationConnectionId));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P5-0010")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RetrySourceConnectionIdLength_IsEightBits()
    {
        foreach (RetryPacketCase testCase in RetryPacketCases())
        {
            QuicLongHeaderPacket header = AssertRetryPacketRoundTrip(testCase);

            Assert.Equal(testCase.SourceConnectionIdLength, header.SourceConnectionIdLength);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P5-0011")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RetrySourceConnectionId_IsZeroToTwentyBytes()
    {
        foreach (RetryPacketCase testCase in RetryPacketCases())
        {
            QuicLongHeaderPacket header = AssertRetryPacketRoundTrip(testCase);

            Assert.InRange(header.SourceConnectionId.Length, 0, 20);
            Assert.Equal(testCase.SourceConnectionIdLength, header.SourceConnectionId.Length);
            Assert.True(SequentialBytes(0x50, testCase.SourceConnectionIdLength).AsSpan()
                .SequenceEqual(header.SourceConnectionId));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P5-0012")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RetryIntegrityTag_IsAlwaysTrailingSixteenBytes()
    {
        foreach (RetryPacketCase testCase in RetryPacketCases())
        {
            RetryPacketFields fields = ParseRetryFields(AssertRetryPacketRoundTrip(testCase));

            Assert.Equal(QuicRetryIntegrity.RetryIntegrityTagLength, fields.RetryIntegrityTag.Length);
            Assert.True(SequentialBytes(0xA0, QuicRetryIntegrity.RetryIntegrityTagLength).AsSpan()
                .SequenceEqual(fields.RetryIntegrityTag));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P5-0013")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RetryPacket_HasNoProtectedPacketNumberSpace()
    {
        foreach (RetryPacketCase testCase in RetryPacketCases())
        {
            byte[] packet = BuildRetryPacket(testCase);
            QuicLongHeaderPacket header = AssertRetryPacketRoundTrip(testCase);

            Assert.False(QuicPacketParser.TryGetPacketNumberSpace(packet, out _));
            Assert.Equal(
                testCase.RetryTokenLength + QuicRetryIntegrity.RetryIntegrityTagLength,
                header.VersionSpecificData.Length);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P5-0014")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RetryMetadataParser_IgnoresAllUnusedBitValues()
    {
        foreach (byte unusedBits in Enumerable.Range(0, 16).Select(value => (byte)value))
        {
            byte[] retryPacket = BuildValidRetryPacketWithUnusedBits(unusedBits);

            Assert.True(QuicRetryIntegrity.TryValidateRetryPacketIntegrity(OriginalDestinationConnectionId, retryPacket));
            Assert.True(QuicPacketParser.TryParseLongHeader(retryPacket, out QuicLongHeaderPacket header));
            Assert.Equal(unusedBits, header.TypeSpecificBits);
            Assert.True(QuicRetryIntegrity.TryParseRetryBootstrapMetadata(
                OriginalDestinationConnectionId,
                retryPacket,
                out QuicRetryBootstrapMetadata retryMetadata));
            Assert.Equal(ValidRetryToken, retryMetadata.RetryToken);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P5-0015")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RetryPacket_ContainsLongHeaderPlusRetryTokenAndIntegrityTag()
    {
        foreach (RetryPacketCase testCase in RetryPacketCases())
        {
            QuicLongHeaderPacket header = AssertRetryPacketRoundTrip(testCase);
            RetryPacketFields fields = ParseRetryFields(header);

            Assert.Equal(testCase.DestinationConnectionIdLength, header.DestinationConnectionIdLength);
            Assert.Equal(testCase.SourceConnectionIdLength, header.SourceConnectionIdLength);
            Assert.Equal(testCase.RetryTokenLength, fields.RetryToken.Length);
            Assert.Equal(QuicRetryIntegrity.RetryIntegrityTagLength, fields.RetryIntegrityTag.Length);
            Assert.True(SequentialBytes(0x80, testCase.RetryTokenLength).AsSpan().SequenceEqual(fields.RetryToken));
        }
    }

    private static readonly byte[] OriginalDestinationConnectionId =
    [
        0x11, 0x12, 0x13, 0x14,
    ];

    private static readonly byte[] ValidRetryPacketDestinationConnectionId =
    [
        0x20, 0x21, 0x22, 0x23,
    ];

    private static readonly byte[] ValidRetrySourceConnectionId =
    [
        0x31, 0x32, 0x33,
    ];

    private static readonly byte[] ValidRetryToken =
    [
        0x41, 0x42, 0x43, 0x44,
    ];

    private static IEnumerable<RetryPacketCase> RetryPacketCases()
    {
        foreach (byte unusedBits in new byte[] { 0, 1, 5, 10, 15 })
        {
            yield return new RetryPacketCase(
                unusedBits,
                DestinationConnectionIdLength: 0,
                SourceConnectionIdLength: 0,
                RetryTokenLength: 0);
            yield return new RetryPacketCase(
                unusedBits,
                DestinationConnectionIdLength: 8,
                SourceConnectionIdLength: 4,
                RetryTokenLength: 4);
            yield return new RetryPacketCase(
                unusedBits,
                DestinationConnectionIdLength: 20,
                SourceConnectionIdLength: 20,
                RetryTokenLength: 64);
        }
    }

    private static byte[] BuildRetryPacket(RetryPacketCase testCase)
    {
        return QuicRetryPacketRequirementTestData.BuildRetryPacket(
            destinationConnectionId: SequentialBytes(0xD0, testCase.DestinationConnectionIdLength),
            sourceConnectionId: SequentialBytes(0x50, testCase.SourceConnectionIdLength),
            retryToken: SequentialBytes(0x80, testCase.RetryTokenLength),
            retryIntegrityTag: SequentialBytes(0xA0, QuicRetryIntegrity.RetryIntegrityTagLength),
            unusedBits: testCase.UnusedBits);
    }

    private static QuicLongHeaderPacket AssertRetryPacketRoundTrip(RetryPacketCase testCase)
    {
        byte[] packet = BuildRetryPacket(testCase);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(QuicHeaderForm.Long, header.HeaderForm);
        Assert.Equal(QuicVersionNegotiation.Version1, header.Version);
        Assert.Equal((byte)QuicLongPacketTypeBits.Retry, header.LongPacketTypeBits);
        return header;
    }

    private static RetryPacketFields ParseRetryFields(QuicLongHeaderPacket header)
    {
        Assert.True(header.VersionSpecificData.Length >= QuicRetryIntegrity.RetryIntegrityTagLength);

        ReadOnlySpan<byte> retryToken =
            header.VersionSpecificData[..^QuicRetryIntegrity.RetryIntegrityTagLength];
        ReadOnlySpan<byte> retryIntegrityTag =
            header.VersionSpecificData[^QuicRetryIntegrity.RetryIntegrityTagLength..];

        return new RetryPacketFields(retryToken.ToArray(), retryIntegrityTag.ToArray());
    }

    private static byte[] BuildValidRetryPacketWithUnusedBits(byte unusedBits)
    {
        byte[] retryPacket = QuicRetryPacketRequirementTestData.BuildRetryPacket(
            destinationConnectionId: ValidRetryPacketDestinationConnectionId,
            sourceConnectionId: ValidRetrySourceConnectionId,
            retryToken: ValidRetryToken,
            unusedBits: unusedBits);

        Assert.True(QuicRetryIntegrity.TryGenerateRetryIntegrityTag(
            OriginalDestinationConnectionId,
            retryPacket.AsSpan(0, retryPacket.Length - QuicRetryIntegrity.RetryIntegrityTagLength),
            retryPacket.AsSpan(retryPacket.Length - QuicRetryIntegrity.RetryIntegrityTagLength),
            out int integrityTagBytesWritten));
        Assert.Equal(QuicRetryIntegrity.RetryIntegrityTagLength, integrityTagBytesWritten);
        return retryPacket;
    }

    private static byte[] SequentialBytes(byte seed, int length)
    {
        byte[] bytes = new byte[length];
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = unchecked((byte)(seed + i));
        }

        return bytes;
    }

    private readonly record struct RetryPacketCase(
        byte UnusedBits,
        int DestinationConnectionIdLength,
        int SourceConnectionIdLength,
        int RetryTokenLength);

    private readonly record struct RetryPacketFields(
        byte[] RetryToken,
        byte[] RetryIntegrityTag);
}
