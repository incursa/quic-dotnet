namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S7P5-0001")]
public sealed class REQ_QUIC_RFC9000_S7P5_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void Fuzz_CryptoBuffer_ReconstructsShuffledFramesWithinMinimumCapacity()
    {
        Random random = new(0x5150_2030);

        for (int iteration = 0; iteration < 16; iteration++)
        {
            const int totalLength = 4096;
            byte[] payload = new byte[totalLength];
            random.NextBytes(payload);

            List<(ulong Offset, byte[] Data)> frames = [];
            int consumed = 0;
            while (consumed < totalLength)
            {
                int chunkLength = Math.Min(random.Next(1, 64), totalLength - consumed);
                frames.Add(((ulong)consumed, payload.AsSpan(consumed, chunkLength).ToArray()));
                consumed += chunkLength;
            }

            frames = frames.OrderBy(_ => random.Next()).ToList();

            QuicCryptoBuffer buffer = new();
            Assert.Equal(4096, buffer.Capacity);

            foreach (var (offset, data) in frames)
            {
                Assert.True(buffer.TryAddFrame(new QuicCryptoFrame(offset, data), out QuicCryptoBufferResult result));
                Assert.Equal(QuicCryptoBufferResult.Buffered, result);
            }

            byte[] reconstructed = new byte[totalLength];
            Assert.True(buffer.TryDequeueContiguousData(reconstructed, out int bytesWritten));
            Assert.Equal(totalLength, bytesWritten);
            Assert.True(payload.AsSpan().SequenceEqual(reconstructed));
            Assert.Equal(0, buffer.BufferedBytes);
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryDequeueContiguousData_ConsumesASingleContiguousFrame()
    {
        QuicCryptoBuffer buffer = new();
        byte[] payload = [0x01, 0x02, 0x03, 0x04];

        Assert.True(buffer.TryAddFrame(new QuicCryptoFrame(0, payload), out QuicCryptoBufferResult addResult));
        Assert.Equal(QuicCryptoBufferResult.Buffered, addResult);

        Span<byte> reconstructed = stackalloc byte[payload.Length];
        Assert.True(buffer.TryDequeueContiguousData(reconstructed, out ulong offset, out int bytesWritten));
        Assert.Equal(0UL, offset);
        Assert.Equal(payload.Length, bytesWritten);
        Assert.True(payload.AsSpan().SequenceEqual(reconstructed[..bytesWritten]));
        Assert.Equal(0, buffer.BufferedBytes);
    }
}
