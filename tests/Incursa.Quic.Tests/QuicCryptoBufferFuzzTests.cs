namespace Incursa.Quic.Tests;

public sealed class QuicCryptoBufferFuzzTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S7P5-0001")]
    [Requirement("REQ-QUIC-RFC9000-S7P5-0002")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void Fuzz_CryptoBuffer_ReconstructsShuffledFrames()
    {
        Random random = new(0x5150_2030);

        for (int iteration = 0; iteration < 64; iteration++)
        {
            int totalLength = random.Next(1, 64);
            byte[] payload = new byte[totalLength];
            random.NextBytes(payload);

            List<(ulong Offset, byte[] Data)> frames = [];
            int consumed = 0;
            while (consumed < totalLength)
            {
                int chunkLength = Math.Min(random.Next(1, 8), totalLength - consumed);
                frames.Add(((ulong)consumed, payload.AsSpan(consumed, chunkLength).ToArray()));
                consumed += chunkLength;
            }

            frames = frames.OrderBy(_ => random.Next()).ToList();

            QuicCryptoBuffer buffer = new(8192);
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
}
