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
}
