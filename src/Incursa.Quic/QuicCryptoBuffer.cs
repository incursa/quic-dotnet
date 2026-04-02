namespace Incursa.Quic;

/// <summary>
/// Describes the outcome of buffering a CRYPTO frame.
/// </summary>
public enum QuicCryptoBufferResult
{
    /// <summary>
    /// The frame was buffered.
    /// </summary>
    Buffered = 0,

    /// <summary>
    /// The frame was discarded after handshake completion and the packet should still be acknowledged.
    /// </summary>
    DiscardedAndAcknowledged = 1,

    /// <summary>
    /// The frame could not be buffered and the connection should be closed with CRYPTO_BUFFER_EXCEEDED.
    /// </summary>
    BufferExceeded = 2,
}

/// <summary>
/// Buffers CRYPTO frames in offset order for handshake processing.
/// </summary>
public sealed class QuicCryptoBuffer
{
    private const int MinimumCapacity = 4096;
    private readonly List<Entry> entries = [];
    private int bufferedBytes;
    private ulong nextReadOffset;
    private bool discardFutureFrames;

    /// <summary>
    /// Initializes a CRYPTO buffer with the minimum RFC 9000 capacity.
    /// </summary>
    public QuicCryptoBuffer()
        : this(MinimumCapacity)
    {
    }

    /// <summary>
    /// Initializes a CRYPTO buffer with a specific capacity.
    /// </summary>
    /// <param name="capacity">The number of bytes the buffer may hold.</param>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="capacity"/> is below 4096 bytes.</exception>
    public QuicCryptoBuffer(int capacity)
    {
        if (capacity < MinimumCapacity)
        {
            throw new ArgumentOutOfRangeException(nameof(capacity));
        }

        Capacity = capacity;
    }

    /// <summary>
    /// Gets the configured buffer capacity.
    /// </summary>
    public int Capacity { get; }

    /// <summary>
    /// Gets or sets whether the handshake has completed.
    /// </summary>
    public bool HandshakeComplete { get; set; }

    /// <summary>
    /// Gets or sets whether overflow after handshake completion should discard future CRYPTO frames.
    /// </summary>
    public bool DiscardOverflowFramesAfterHandshakeComplete { get; set; } = true;

    /// <summary>
    /// Gets the number of buffered bytes that have not yet been dequeued.
    /// </summary>
    public int BufferedBytes => bufferedBytes;

    /// <summary>
    /// Attempts to buffer a CRYPTO frame.
    /// </summary>
    public bool TryAddFrame(QuicCryptoFrame frame, out QuicCryptoBufferResult result)
    {
        result = QuicCryptoBufferResult.Buffered;

        if (discardFutureFrames)
        {
            result = QuicCryptoBufferResult.DiscardedAndAcknowledged;
            return true;
        }

        byte[] data = frame.CryptoData.ToArray();
        if (data.Length == 0)
        {
            return true;
        }

        if (frame.Offset > QuicVariableLengthInteger.MaxValue - (ulong)data.Length)
        {
            result = QuicCryptoBufferResult.BufferExceeded;
            return false;
        }

        if (frame.Offset < nextReadOffset)
        {
            int trim = (int)(nextReadOffset - frame.Offset);
            if (trim >= data.Length)
            {
                return true;
            }

            data = data[trim..];
            frame = new QuicCryptoFrame(nextReadOffset, data);
        }

        if (!TryInsertFrameData(frame.Offset, data, out int newBufferedBytes))
        {
            if (HandshakeComplete && DiscardOverflowFramesAfterHandshakeComplete)
            {
                discardFutureFrames = true;
                result = QuicCryptoBufferResult.DiscardedAndAcknowledged;
                return true;
            }

            result = QuicCryptoBufferResult.BufferExceeded;
            return true;
        }

        bufferedBytes = newBufferedBytes;
        result = QuicCryptoBufferResult.Buffered;
        return true;
    }

    /// <summary>
    /// Copies contiguous buffered CRYPTO data into <paramref name="destination"/>.
    /// </summary>
    public bool TryDequeueContiguousData(Span<byte> destination, out int bytesWritten)
    {
        bytesWritten = 0;
        if (destination.IsEmpty || entries.Count == 0)
        {
            return false;
        }

        ulong expectedOffset = nextReadOffset;
        int destinationIndex = 0;

        while (destinationIndex < destination.Length && entries.Count > 0)
        {
            Entry entry = entries[0];
            if (entry.Offset > expectedOffset)
            {
                break;
            }

            if (entry.Offset < expectedOffset)
            {
                int skip = (int)(expectedOffset - entry.Offset);
                if (skip >= entry.Data.Length)
                {
                    bufferedBytes -= entry.Data.Length;
                    entries.RemoveAt(0);
                    continue;
                }

                entry = new Entry(expectedOffset, entry.Data[skip..]);
            }

            int bytesToCopy = Math.Min(entry.Data.Length, destination.Length - destinationIndex);
            entry.Data.AsSpan(0, bytesToCopy).CopyTo(destination[destinationIndex..]);
            destinationIndex += bytesToCopy;
            expectedOffset += (ulong)bytesToCopy;
            bufferedBytes -= bytesToCopy;

            if (bytesToCopy == entry.Data.Length)
            {
                entries.RemoveAt(0);
            }
            else
            {
                entries[0] = new Entry(entry.Offset + (ulong)bytesToCopy, entry.Data[bytesToCopy..]);
                break;
            }
        }

        nextReadOffset = expectedOffset;
        bytesWritten = destinationIndex;
        return bytesWritten > 0;
    }

    private bool TryInsertFrameData(ulong offset, byte[] data, out int newBufferedBytes)
    {
        List<Entry> updated = new(entries.Count + 2);
        int currentIndex = 0;
        ulong currentOffset = offset;
        ulong endOffset = offset + (ulong)data.Length;
        int dataIndex = 0;

        while (currentIndex < entries.Count && entries[currentIndex].End <= currentOffset)
        {
            updated.Add(entries[currentIndex++]);
        }

        while (currentIndex < entries.Count && currentOffset < endOffset)
        {
            Entry existing = entries[currentIndex];

            if (existing.Offset > currentOffset)
            {
                ulong gapEnd = Math.Min(existing.Offset, endOffset);
                int gapLength = (int)(gapEnd - currentOffset);
                if (gapLength > 0)
                {
                    updated.Add(new Entry(currentOffset, data[dataIndex..(dataIndex + gapLength)]));
                    dataIndex += gapLength;
                    currentOffset += (ulong)gapLength;
                }
            }

            if (currentOffset >= endOffset)
            {
                break;
            }

            if (existing.Offset < currentOffset)
            {
                ulong skipEnd = Math.Min(existing.End, endOffset);
                if (skipEnd > currentOffset)
                {
                    dataIndex += (int)(skipEnd - currentOffset);
                    currentOffset = skipEnd;
                }
            }

            updated.Add(existing);
            currentIndex++;
        }

        if (currentOffset < endOffset)
        {
            int tailLength = (int)(endOffset - currentOffset);
            updated.Add(new Entry(currentOffset, data[dataIndex..(dataIndex + tailLength)]));
        }

        while (currentIndex < entries.Count)
        {
            updated.Add(entries[currentIndex++]);
        }

        newBufferedBytes = 0;
        foreach (Entry entry in updated)
        {
            newBufferedBytes += entry.Data.Length;
        }

        if (newBufferedBytes > Capacity)
        {
            return false;
        }

        entries.Clear();
        entries.AddRange(updated);
        return true;
    }

    private readonly record struct Entry(ulong Offset, byte[] Data)
    {
        public ulong End => Offset + (ulong)Data.Length;
    }
}
