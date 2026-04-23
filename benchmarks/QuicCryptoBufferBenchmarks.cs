using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks CRYPTO stream buffering for shuffled and overlapping frame arrivals.
/// </summary>
[MemoryDiagnoser]
public class QuicCryptoBufferBenchmarks
{
    private byte[] payload = [];
    private byte[] destination = [];
    private (ulong Offset, byte[] Data)[] frames = [];

    [Params(false, true)]
    public bool IncludeOverlap { get; set; }

    /// <summary>
    /// Prepares a deterministic 4096-byte CRYPTO stream split into shuffled frames.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        Random random = new(0x5150_2030);
        payload = new byte[4096];
        random.NextBytes(payload);
        destination = new byte[payload.Length];

        List<(ulong Offset, byte[] Data)> preparedFrames = [];
        int consumed = 0;
        while (consumed < payload.Length)
        {
            int chunkLength = Math.Min(random.Next(1, 64), payload.Length - consumed);
            preparedFrames.Add(((ulong)consumed, payload.AsSpan(consumed, chunkLength).ToArray()));
            consumed += chunkLength;
        }

        preparedFrames = preparedFrames.OrderBy(_ => random.Next()).ToList();
        if (IncludeOverlap)
        {
            preparedFrames.AddRange(preparedFrames.Take(4));
            for (int overlap = 0; overlap < 4; overlap++)
            {
                int start = random.Next(0, payload.Length - 32);
                int length = Math.Min(random.Next(1, 96), payload.Length - start);
                preparedFrames.Add(((ulong)start, payload.AsSpan(start, length).ToArray()));
            }

            preparedFrames = preparedFrames.OrderBy(_ => random.Next()).ToList();
        }

        frames = preparedFrames.ToArray();
    }

    /// <summary>
    /// Measures buffering and draining one minimum-capacity CRYPTO stream.
    /// </summary>
    [Benchmark]
    public int BufferAndDrainMinimumCryptoStream()
    {
        QuicCryptoBuffer buffer = new();
        foreach ((ulong offset, byte[] data) in frames)
        {
            if (!buffer.TryAddFrame(new QuicCryptoFrame(offset, data), out QuicCryptoBufferResult result)
                || result != QuicCryptoBufferResult.Buffered)
            {
                return -1;
            }
        }

        return buffer.TryDequeueContiguousData(destination, out int bytesWritten)
            ? bytesWritten ^ buffer.BufferedBytes
            : -1;
    }
}
