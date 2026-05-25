namespace Incursa.Quic.Tests;

public sealed class QuicRetryIntegrityUnitTests
{
    private static readonly byte[] ClientInitialDestinationConnectionId =
    [
        0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08,
    ];

    private static readonly byte[] RetrySourceConnectionId =
    [
        0xF0, 0x67, 0xA5, 0x50, 0x2A, 0x42, 0x62, 0xB5,
    ];

    private static readonly byte[] RetryToken =
    [
        0x74, 0x6F, 0x6B, 0x65, 0x6E,
    ];

    private static readonly byte[] ExpectedRetryIntegrityTag =
    [
        0x04, 0xA2, 0x65, 0xBA, 0x2E, 0xFF, 0x4D, 0x82,
        0x90, 0x58, 0xFB, 0x3F, 0x0F, 0x24, 0x96, 0xBA,
    ];

    [Fact]
    public void TryGenerateRetryIntegrityTag_ProducesTheRFCAppendixASampleTag()
    {
        byte[] retryPacketWithoutIntegrityTag = QuicRetryPacketRequirementTestData.BuildRetryPacket(
            destinationConnectionId: [],
            sourceConnectionId: RetrySourceConnectionId,
            retryToken: RetryToken,
            retryIntegrityTag: [],
            unusedBits: 0x0F);

        Span<byte> retryIntegrityTag = stackalloc byte[QuicRetryIntegrity.RetryIntegrityTagLength];
        Assert.True(QuicRetryIntegrity.TryGenerateRetryIntegrityTag(
            ClientInitialDestinationConnectionId,
            retryPacketWithoutIntegrityTag,
            retryIntegrityTag,
            out int bytesWritten));

        Assert.Equal(QuicRetryIntegrity.RetryIntegrityTagLength, bytesWritten);
        Assert.True(ExpectedRetryIntegrityTag.AsSpan().SequenceEqual(retryIntegrityTag));
    }

    [Fact]
    public void TryValidateRetryPacketIntegrity_AcceptsTheRFCAppendixASamplePacket()
    {
        byte[] retryPacket = QuicRetryPacketRequirementTestData.BuildRetryPacket(
            destinationConnectionId: [],
            sourceConnectionId: RetrySourceConnectionId,
            retryToken: RetryToken,
            retryIntegrityTag: ExpectedRetryIntegrityTag,
            unusedBits: 0x0F);

        Assert.True(QuicRetryIntegrity.TryValidateRetryPacketIntegrity(
            ClientInitialDestinationConnectionId,
            retryPacket));
    }

    [Fact]
    public void TryValidateRetryPacketIntegrity_RejectsRetryPacketsWhenTheOriginalDestinationConnectionIdDoesNotMatch()
    {
        byte[] retryPacket = QuicRetryPacketRequirementTestData.BuildRetryPacket(
            destinationConnectionId: [],
            sourceConnectionId: RetrySourceConnectionId,
            retryToken: RetryToken,
            retryIntegrityTag: ExpectedRetryIntegrityTag,
            unusedBits: 0x0F);

        Assert.False(QuicRetryIntegrity.TryValidateRetryPacketIntegrity(
            [0x99, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08],
            retryPacket));
    }

    [Fact]
    public void TryValidateRetryPacketIntegrity_RejectsTruncatedAndTooShortRetryPackets()
    {
        byte[] retryPacket = QuicRetryPacketRequirementTestData.BuildRetryPacket(
            destinationConnectionId: [],
            sourceConnectionId: RetrySourceConnectionId,
            retryToken: RetryToken,
            retryIntegrityTag: ExpectedRetryIntegrityTag,
            unusedBits: 0x0F);

        Assert.False(QuicRetryIntegrity.TryValidateRetryPacketIntegrity(
            ClientInitialDestinationConnectionId,
            retryPacket[..^1]));

        Assert.False(QuicRetryIntegrity.TryValidateRetryPacketIntegrity(
            ClientInitialDestinationConnectionId,
            retryPacket[..(QuicRetryIntegrity.RetryIntegrityTagLength - 1)]));
    }

    [Fact]
    public void TryGenerateRetryIntegrityTag_RejectsDestinationBuffersThatAreTooSmall()
    {
        byte[] retryPacketWithoutIntegrityTag = QuicRetryPacketRequirementTestData.BuildRetryPacket(
            destinationConnectionId: [],
            sourceConnectionId: RetrySourceConnectionId,
            retryToken: RetryToken,
            retryIntegrityTag: [],
            unusedBits: 0x0F);

        Span<byte> retryIntegrityTag = stackalloc byte[QuicRetryIntegrity.RetryIntegrityTagLength - 1];
        Assert.False(QuicRetryIntegrity.TryGenerateRetryIntegrityTag(
            ClientInitialDestinationConnectionId,
            retryPacketWithoutIntegrityTag,
            retryIntegrityTag,
            out int bytesWritten));
        Assert.Equal(0, bytesWritten);
    }

    [Fact]
    public void TryBuildRetryPacket_Version2_ProducesValidRetryIntegrity()
    {
        Assert.True(QuicRetryIntegrity.TryBuildRetryPacket(
            QuicVersionNegotiation.Version2,
            ClientInitialDestinationConnectionId,
            [0x20, 0x21, 0x22, 0x23],
            RetrySourceConnectionId,
            RetryToken,
            out byte[] retryPacket));

        Assert.True(QuicRetryIntegrity.TryValidateRetryPacketIntegrity(ClientInitialDestinationConnectionId, retryPacket));

        Assert.True(QuicRetryIntegrity.TryParseRetryBootstrapMetadata(
            QuicVersionNegotiation.Version2,
            ClientInitialDestinationConnectionId,
            retryPacket,
            out QuicRetryBootstrapMetadata retryMetadata));
        Assert.Equal(RetrySourceConnectionId, retryMetadata.RetrySourceConnectionId);
        Assert.Equal(RetryToken, retryMetadata.RetryToken);
    }

    [Fact]
    public void TryParseRetryBootstrapMetadata_VersionAwareOverload_RejectsVersionMismatches()
    {
        Assert.True(QuicRetryIntegrity.TryBuildRetryPacket(
            QuicVersionNegotiation.Version2,
            ClientInitialDestinationConnectionId,
            [0x20, 0x21, 0x22, 0x23],
            RetrySourceConnectionId,
            RetryToken,
            out byte[] retryPacket));

        Assert.False(QuicRetryIntegrity.TryParseRetryBootstrapMetadata(
            QuicVersionNegotiation.Version1,
            ClientInitialDestinationConnectionId,
            retryPacket,
            out _));
    }

    [Fact]
    public void TryGenerateRetryIntegrityTag_Version2_DiffersFromVersion1Material()
    {
        byte[] retryPacketV1WithoutIntegrityTag = QuicRetryPacketRequirementTestData.BuildRetryPacket(
            destinationConnectionId: [],
            sourceConnectionId: RetrySourceConnectionId,
            retryToken: RetryToken,
            retryIntegrityTag: [],
            version: QuicVersionNegotiation.Version1,
            unusedBits: 0x0F);
        byte[] retryPacketV2WithoutIntegrityTag = QuicRetryPacketRequirementTestData.BuildRetryPacket(
            destinationConnectionId: [],
            sourceConnectionId: RetrySourceConnectionId,
            retryToken: RetryToken,
            retryIntegrityTag: [],
            version: QuicVersionNegotiation.Version2,
            unusedBits: 0x0F);

        Span<byte> version1Tag = stackalloc byte[QuicRetryIntegrity.RetryIntegrityTagLength];
        Span<byte> version2Tag = stackalloc byte[QuicRetryIntegrity.RetryIntegrityTagLength];

        Assert.True(QuicRetryIntegrity.TryGenerateRetryIntegrityTag(
            ClientInitialDestinationConnectionId,
            retryPacketV1WithoutIntegrityTag,
            version1Tag,
            out int version1BytesWritten));

        Assert.True(QuicRetryIntegrity.TryGenerateRetryIntegrityTag(
            ClientInitialDestinationConnectionId,
            retryPacketV2WithoutIntegrityTag,
            version2Tag,
            out int version2BytesWritten));

        Assert.Equal(QuicRetryIntegrity.RetryIntegrityTagLength, version1BytesWritten);
        Assert.Equal(QuicRetryIntegrity.RetryIntegrityTagLength, version2BytesWritten);
        Assert.False(version1Tag.SequenceEqual(version2Tag));
    }
}
