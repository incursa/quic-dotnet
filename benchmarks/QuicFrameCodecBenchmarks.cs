using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks the CRYPTO, ACK, and STREAM frame parse and format hot paths.
/// </summary>
[MemoryDiagnoser]
public class QuicFrameCodecBenchmarks
{
    private byte[] ackFrame = [];
    private byte[] ackEcnFrame = [];
    private QuicAckFrame ackTemplate = new();
    private QuicAckFrame ackEcnTemplate = new();
    private byte[] cryptoFrame = [];
    private byte[] cryptoData = [];
    private byte[] largeStreamData = [];
    private byte[] streamData = [];
    private byte[] streamsBlockedFrame = [];
    private QuicStreamsBlockedFrame streamsBlockedTemplate;
    private byte[] destination = [];

    /// <summary>
    /// Prepares representative ACK, CRYPTO, and STREAM payloads plus output buffers.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        cryptoData = [0xAA, 0xBB, 0xCC, 0xDD];
        cryptoFrame = QuicBenchmarkData.BuildCryptoFrame(0x1122_3344, cryptoData);
        streamData = [0x10, 0x11, 0x12, 0x13];
        largeStreamData = new byte[512];
        for (int i = 0; i < largeStreamData.Length; i++)
        {
            largeStreamData[i] = (byte)i;
        }

        ackTemplate = new QuicAckFrame
        {
            FrameType = 0x02,
            LargestAcknowledged = 0x1234,
            AckDelay = 0x20,
            FirstAckRange = 3,
            AdditionalRanges =
            [
                new QuicAckRange(1, 2, 0x122C, 0x122E),
                new QuicAckRange(0, 0, 0x122A, 0x122A),
            ],
        };

        ackEcnTemplate = new QuicAckFrame
        {
            FrameType = 0x03,
            LargestAcknowledged = 0x1234,
            AckDelay = 0x20,
            FirstAckRange = 3,
            AdditionalRanges =
            [
                new QuicAckRange(1, 2, 0x122C, 0x122E),
                new QuicAckRange(0, 0, 0x122A, 0x122A),
            ],
            EcnCounts = new QuicEcnCounts(0x11, 0x12, 0x13),
        };

        byte[] ackDestination = new byte[64];
        if (!QuicFrameCodec.TryFormatAckFrame(ackTemplate, ackDestination, out int bytesWritten))
        {
            throw new InvalidOperationException("Failed to prepare an ACK frame benchmark payload.");
        }

        ackFrame = ackDestination[..bytesWritten].ToArray();
        byte[] ackEcnDestination = new byte[64];
        if (!QuicFrameCodec.TryFormatAckFrame(ackEcnTemplate, ackEcnDestination, out int ackEcnBytesWritten))
        {
            throw new InvalidOperationException("Failed to prepare an ACK_ECN frame benchmark payload.");
        }

        ackEcnFrame = ackEcnDestination[..ackEcnBytesWritten].ToArray();
        streamsBlockedTemplate = new QuicStreamsBlockedFrame(isBidirectional: true, maximumStreams: 4);
        byte[] streamsBlockedDestination = new byte[16];
        if (!QuicFrameCodec.TryFormatStreamsBlockedFrame(streamsBlockedTemplate, streamsBlockedDestination, out int streamsBlockedBytesWritten))
        {
            throw new InvalidOperationException("Failed to prepare a STREAMS_BLOCKED frame benchmark payload.");
        }

        streamsBlockedFrame = streamsBlockedDestination[..streamsBlockedBytesWritten].ToArray();
        destination = new byte[2048];
    }

    /// <summary>
    /// Measures ACK frame parsing.
    /// </summary>
    [Benchmark]
    public int ParseAckFrame()
    {
        return QuicFrameCodec.TryParseAckFrame(ackFrame, out QuicAckFrame frame, out int bytesConsumed)
            ? bytesConsumed
                ^ unchecked((int)frame.LargestAcknowledged)
                ^ (int)frame.AckDelay
                ^ frame.AdditionalRanges.Length
            : -1;
    }

    /// <summary>
    /// Measures ACK frame formatting.
    /// </summary>
    [Benchmark]
    public int FormatAckFrame()
    {
        return QuicFrameCodec.TryFormatAckFrame(ackTemplate, destination, out int bytesWritten)
            ? bytesWritten
            : -1;
    }

    /// <summary>
    /// Measures ACK_ECN frame parsing.
    /// </summary>
    [Benchmark]
    public int ParseAckEcnFrame()
    {
        return QuicFrameCodec.TryParseAckFrame(ackEcnFrame, out QuicAckFrame frame, out int bytesConsumed)
            ? bytesConsumed
                ^ unchecked((int)frame.LargestAcknowledged)
                ^ (int)frame.AckDelay
                ^ frame.AdditionalRanges.Length
                ^ unchecked((int)(frame.EcnCounts?.Ect0Count ?? 0))
                ^ unchecked((int)(frame.EcnCounts?.Ect1Count ?? 0))
                ^ unchecked((int)(frame.EcnCounts?.EcnCeCount ?? 0))
            : -1;
    }

    /// <summary>
    /// Measures ACK_ECN frame formatting.
    /// </summary>
    [Benchmark]
    public int FormatAckEcnFrame()
    {
        return QuicFrameCodec.TryFormatAckFrame(ackEcnTemplate, destination, out int bytesWritten)
            ? bytesWritten
            : -1;
    }

    /// <summary>
    /// Measures CRYPTO frame parsing.
    /// </summary>
    [Benchmark]
    public int ParseCryptoFrame()
    {
        return QuicFrameCodec.TryParseCryptoFrame(cryptoFrame, out QuicCryptoFrame frame, out int bytesConsumed)
            ? bytesConsumed ^ unchecked((int)frame.Offset) ^ frame.CryptoData.Length
            : -1;
    }

    /// <summary>
    /// Measures CRYPTO frame formatting.
    /// </summary>
    [Benchmark]
    public int FormatCryptoFrame()
    {
        QuicCryptoFrame frame = new(0x1122_3344, cryptoData);
        return QuicFrameCodec.TryFormatCryptoFrame(frame, destination, out int bytesWritten)
            ? bytesWritten
            : -1;
    }

    /// <summary>
    /// Measures STREAM frame formatting with a larger payload.
    /// </summary>
    [Benchmark]
    public int FormatLargeStreamFrame()
    {
        return QuicFrameCodec.TryFormatStreamFrame(
            0x0F,
            0x1234,
            0x20,
            largeStreamData,
            destination,
            out int bytesWritten)
            ? bytesWritten
            : -1;
    }

    /// <summary>
    /// Measures STREAM frame formatting.
    /// </summary>
    [Benchmark]
    public int FormatStreamFrame()
    {
        return QuicFrameCodec.TryFormatStreamFrame(
            0x0F,
            0x1234,
            0x20,
            streamData,
            destination,
            out int bytesWritten)
            ? bytesWritten
            : -1;
    }

    /// <summary>
    /// Measures STREAMS_BLOCKED frame parsing.
    /// </summary>
    [Benchmark]
    public int ParseStreamsBlockedFrame()
    {
        return QuicFrameCodec.TryParseStreamsBlockedFrame(
            streamsBlockedFrame,
            out QuicStreamsBlockedFrame frame,
            out int bytesConsumed)
            ? bytesConsumed ^ (frame.IsBidirectional ? 1 : 0) ^ unchecked((int)frame.MaximumStreams)
            : -1;
    }

    /// <summary>
    /// Measures STREAMS_BLOCKED frame formatting.
    /// </summary>
    [Benchmark]
    public int FormatStreamsBlockedFrame()
    {
        return QuicFrameCodec.TryFormatStreamsBlockedFrame(streamsBlockedTemplate, destination, out int bytesWritten)
            ? bytesWritten
            : -1;
    }
}
