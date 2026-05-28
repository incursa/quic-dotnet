// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9369-S3-0003")]
public sealed class REQ_QUIC_RFC9369_S3_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryBuildRetryPacket_Version2_ProducesValidRetryIntegrity()
    {
        Assert.True(QuicRetryIntegrity.TryBuildRetryPacket(
            QuicVersionNegotiation.Version2,
            [0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08],
            [0xCD, 0x41, 0x8F, 0x22, 0xA7, 0x5B, 0x10, 0xE4],
            [0xF0, 0x67, 0xA5, 0x50, 0x2A, 0x42, 0x62, 0xB5],
            [0x74, 0x6F, 0x6B, 0x65, 0x6E],
            out byte[] retryPacket));

        Assert.True(QuicRetryIntegrity.TryValidateRetryPacketIntegrity(
            [0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08],
            retryPacket));

        Assert.True(QuicRetryIntegrity.TryParseRetryBootstrapMetadata(
            QuicVersionNegotiation.Version2,
            [0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08],
            retryPacket,
            out QuicRetryBootstrapMetadata metadata));
        Assert.Equal([0xF0, 0x67, 0xA5, 0x50, 0x2A, 0x42, 0x62, 0xB5], metadata.RetrySourceConnectionId);
        Assert.Equal([0x74, 0x6F, 0x6B, 0x65, 0x6E], metadata.RetryToken);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseRetryBootstrapMetadata_VersionAwareOverload_RejectsVersionMismatches()
    {
        Assert.True(QuicRetryIntegrity.TryBuildRetryPacket(
            QuicVersionNegotiation.Version2,
            [0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08],
            [0xCD, 0x41, 0x8F, 0x22, 0xA7, 0x5B, 0x10, 0xE4],
            [0xF0, 0x67, 0xA5, 0x50, 0x2A, 0x42, 0x62, 0xB5],
            [0x74, 0x6F, 0x6B, 0x65, 0x6E],
            out byte[] retryPacket));

        Assert.False(QuicRetryIntegrity.TryParseRetryBootstrapMetadata(
            QuicVersionNegotiation.Version1,
            [0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08],
            retryPacket,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryGenerateRetryIntegrityTag_Version2_DiffersFromVersion1Material()
    {
        byte[] originalDestinationConnectionId = [0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08];
        byte[] retryPacketV1WithoutTag = QuicRetryPacketRequirementTestData.BuildRetryPacket(
            destinationConnectionId: [0xCD, 0x41, 0x8F, 0x22, 0xA7, 0x5B, 0x10, 0xE4],
            sourceConnectionId: [0xF0, 0x67, 0xA5, 0x50, 0x2A, 0x42, 0x62, 0xB5],
            retryToken: [0x74, 0x6F, 0x6B, 0x65, 0x6E],
            retryIntegrityTag: [],
            version: QuicVersionNegotiation.Version1,
            unusedBits: 0x0F);
        byte[] retryPacketV2WithoutTag = QuicRetryPacketRequirementTestData.BuildRetryPacket(
            destinationConnectionId: [0xCD, 0x41, 0x8F, 0x22, 0xA7, 0x5B, 0x10, 0xE4],
            sourceConnectionId: [0xF0, 0x67, 0xA5, 0x50, 0x2A, 0x42, 0x62, 0xB5],
            retryToken: [0x74, 0x6F, 0x6B, 0x65, 0x6E],
            retryIntegrityTag: [],
            version: QuicVersionNegotiation.Version2,
            unusedBits: 0x0F);

        Span<byte> version1Tag = stackalloc byte[QuicRetryIntegrity.RetryIntegrityTagLength];
        Span<byte> version2Tag = stackalloc byte[QuicRetryIntegrity.RetryIntegrityTagLength];

        Assert.True(QuicRetryIntegrity.TryGenerateRetryIntegrityTag(
            originalDestinationConnectionId,
            retryPacketV1WithoutTag,
            version1Tag,
            out int version1BytesWritten));

        Assert.True(QuicRetryIntegrity.TryGenerateRetryIntegrityTag(
            originalDestinationConnectionId,
            retryPacketV2WithoutTag,
            version2Tag,
            out int version2BytesWritten));

        Assert.Equal(QuicRetryIntegrity.RetryIntegrityTagLength, version1BytesWritten);
        Assert.Equal(QuicRetryIntegrity.RetryIntegrityTagLength, version2BytesWritten);
        Assert.False(version1Tag.SequenceEqual(version2Tag));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_Version2RetryIntegrity_RoundTripsRepresentativePackets()
    {
        Random random = new(unchecked((int)0x9369_0003));
        byte[] originalDestinationConnectionId = [0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08];

        for (int iteration = 0; iteration < 32; iteration++)
        {
            byte[] retrySourceConnectionId = RandomBytes(random, 4 + (iteration % 4));
            byte[] retryToken = RandomBytes(random, 5 + (iteration % 5));

            Assert.True(QuicRetryIntegrity.TryBuildRetryPacket(
                QuicVersionNegotiation.Version2,
                originalDestinationConnectionId,
                RandomBytes(random, 4),
                retrySourceConnectionId,
                retryToken,
                out byte[] retryPacket));

            Assert.True(QuicRetryIntegrity.TryValidateRetryPacketIntegrity(
                originalDestinationConnectionId,
                retryPacket));

            Assert.True(QuicRetryIntegrity.TryParseRetryBootstrapMetadata(
                QuicVersionNegotiation.Version2,
                originalDestinationConnectionId,
                retryPacket,
                out QuicRetryBootstrapMetadata metadata));
            Assert.Equal(retrySourceConnectionId, metadata.RetrySourceConnectionId);
            Assert.Equal(retryToken, metadata.RetryToken);
        }
    }

    private static byte[] RandomBytes(Random random, int length)
    {
        byte[] bytes = new byte[length];
        random.NextBytes(bytes);
        return bytes;
    }
}
