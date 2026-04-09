namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-S5-0004")]
public sealed class REQ_QUIC_RFC9001_S5_0004
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
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
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
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
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
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryValidateRetryPacketIntegrity_RejectsATamperedRetryPacket()
    {
        byte[] retryPacket = QuicRetryPacketRequirementTestData.BuildRetryPacket(
            destinationConnectionId: [],
            sourceConnectionId: RetrySourceConnectionId,
            retryToken: RetryToken,
            retryIntegrityTag: ExpectedRetryIntegrityTag,
            unusedBits: 0x0F);

        retryPacket[^1] ^= 0x01;

        Assert.False(QuicRetryIntegrity.TryValidateRetryPacketIntegrity(
            ClientInitialDestinationConnectionId,
            retryPacket));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
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
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryGenerateRetryIntegrityTag_RejectsMalformedOrNonRetryInputs()
    {
        byte[] initialPacket = QuicInitialPacketProtectionTestData.BuildInitialPlaintextPacket(
            destinationConnectionId: [0x01],
            sourceConnectionId: [0x02],
            token: [],
            packetNumber: [0x01],
            plaintextPayload:
            [
                0x10, 0x11, 0x12, 0x13, 0x14,
                0x15, 0x16, 0x17, 0x18, 0x19,
                0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
                0x1F, 0x20, 0x21, 0x22, 0x23,
            ]);

        Span<byte> retryIntegrityTag = stackalloc byte[QuicRetryIntegrity.RetryIntegrityTagLength];

        Assert.False(QuicRetryIntegrity.TryGenerateRetryIntegrityTag(
            ClientInitialDestinationConnectionId,
            initialPacket,
            retryIntegrityTag,
            out _));
        Assert.False(QuicRetryIntegrity.TryValidateRetryPacketIntegrity(
            ClientInitialDestinationConnectionId,
            [0xFF, 0x00, 0x00, 0x00, 0x01]));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RetryIntegrity_RoundTripsRandomValidInputs()
    {
        Random random = new(0x7151_9A2B);
        Span<byte> retryIntegrityTag = stackalloc byte[QuicRetryIntegrity.RetryIntegrityTagLength];

        for (int iteration = 0; iteration < 32; iteration++)
        {
            byte[] clientInitialDestinationConnectionId = QuicHeaderTestData.RandomBytes(random, random.Next(0, 21));
            byte[] retrySourceConnectionId = QuicHeaderTestData.RandomBytes(random, random.Next(0, 21));
            byte[] retryToken = QuicHeaderTestData.RandomBytes(random, random.Next(0, 33));

            byte[] retryPacketWithoutIntegrityTag = QuicRetryPacketRequirementTestData.BuildRetryPacket(
                destinationConnectionId: clientInitialDestinationConnectionId,
                sourceConnectionId: retrySourceConnectionId,
                retryToken: retryToken,
                retryIntegrityTag: []);

            Assert.True(QuicRetryIntegrity.TryGenerateRetryIntegrityTag(
                clientInitialDestinationConnectionId,
                retryPacketWithoutIntegrityTag,
                retryIntegrityTag,
                out int bytesWritten));

            Assert.Equal(QuicRetryIntegrity.RetryIntegrityTagLength, bytesWritten);

            byte[] retryPacket = QuicRetryPacketRequirementTestData.BuildRetryPacket(
                destinationConnectionId: clientInitialDestinationConnectionId,
                sourceConnectionId: retrySourceConnectionId,
                retryToken: retryToken,
                retryIntegrityTag: retryIntegrityTag.ToArray());

            Assert.True(QuicRetryIntegrity.TryValidateRetryPacketIntegrity(
                clientInitialDestinationConnectionId,
                retryPacket));
        }
    }
}
