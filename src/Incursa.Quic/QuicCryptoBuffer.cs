namespace Incursa.Quic;

/// <summary>
/// Describes the outcome of buffering a CRYPTO frame.
/// </summary>
internal enum QuicCryptoBufferResult
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
    internal sealed class QuicCryptoBuffer
{
    /// <summary>
    /// Local implementation floor chosen to keep the CRYPTO buffer comfortably above small handshake bursts.
    /// </summary>
    private const int MinimumCapacity = 4096;
    private readonly List<Entry> entries = [];
    private int bufferedBytes;
    private ulong nextReadOffset;
    private bool discardFutureFrames;

    /// <summary>
    /// Initializes a CRYPTO buffer with the minimum RFC 9000 capacity.
    /// </summary>
    internal QuicCryptoBuffer()
        : this(MinimumCapacity)
    {
    }

    /// <summary>
    /// Initializes a CRYPTO buffer with a specific capacity.
    /// </summary>
    /// <param name="capacity">The number of bytes the buffer may hold.</param>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="capacity"/> is below 4096 bytes.</exception>
    internal QuicCryptoBuffer(int capacity)
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
    internal int Capacity { get; }

    /// <summary>
    /// Gets or sets whether the handshake has completed.
    /// </summary>
    internal bool HandshakeComplete { get; set; }

    /// <summary>
    /// Gets whether future CRYPTO frames are being discarded after overflow or explicit key-transition.
    /// </summary>
    internal bool DiscardingFutureFrames => discardFutureFrames;

    /// <summary>
    /// Gets or sets whether overflow after handshake completion should discard future CRYPTO frames.
    /// </summary>
    internal bool DiscardOverflowFramesAfterHandshakeComplete { get; set; } = true;

    /// <summary>
    /// Gets the number of buffered bytes that have not yet been dequeued.
    /// </summary>
    internal int BufferedBytes => bufferedBytes;

    /// <summary>
    /// Discards all currently buffered CRYPTO data and marks future frames as acknowledged.
    /// </summary>
    internal void DiscardFutureFrames()
    {
        discardFutureFrames = true;
        entries.Clear();
        bufferedBytes = 0;
    }

    /// <summary>
    /// Discards buffered CRYPTO frames when 0-RTT is rejected.
    /// </summary>
    internal void RejectZeroRtt()
    {
        DiscardFutureFrames();
    }

    /// <summary>
    /// Clears buffered CRYPTO data and restarts offset tracking for a new handshake attempt.
    /// </summary>
    internal void Reset()
    {
        entries.Clear();
        bufferedBytes = 0;
        nextReadOffset = 0;
        discardFutureFrames = false;
        HandshakeComplete = false;
        DiscardOverflowFramesAfterHandshakeComplete = true;
    }

    /// <summary>
    /// Attempts to buffer a CRYPTO frame.
    /// </summary>
    internal bool TryAddFrame(QuicCryptoFrame frame, out QuicCryptoBufferResult result)
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
    /// Peeks contiguous buffered CRYPTO data into <paramref name="destination"/> without consuming it.
    /// </summary>
    internal bool TryPeekContiguousData(Span<byte> destination, out ulong offset, out int bytesWritten)
    {
        return TryAccessContiguousData(destination, consume: false, out offset, out bytesWritten);
    }

    /// <summary>
    /// Copies contiguous buffered CRYPTO data into <paramref name="destination"/> and consumes it.
    /// </summary>
    internal bool TryDequeueContiguousData(Span<byte> destination, out ulong offset, out int bytesWritten)
    {
        return TryAccessContiguousData(destination, consume: true, out offset, out bytesWritten);
    }

    /// <summary>
    /// Copies contiguous buffered CRYPTO data into <paramref name="destination"/>.
    /// </summary>
    internal bool TryDequeueContiguousData(Span<byte> destination, out int bytesWritten)
    {
        return TryAccessContiguousData(destination, consume: true, out _, out bytesWritten);
    }

    private bool TryAccessContiguousData(
        Span<byte> destination,
        bool consume,
        out ulong offset,
        out int bytesWritten)
    {
        offset = nextReadOffset;
        bytesWritten = 0;

        if (destination.IsEmpty || entries.Count == 0)
        {
            return false;
        }

        ulong expectedOffset = nextReadOffset;
        int destinationIndex = 0;
        int currentIndex = 0;
        int remainingBufferedBytes = bufferedBytes;
        List<Entry>? retainedEntries = consume ? new List<Entry>(entries.Count) : null;

        while (currentIndex < entries.Count && destinationIndex < destination.Length)
        {
            Entry entry = entries[currentIndex];

            if (entry.Offset > expectedOffset)
            {
                if (consume)
                {
                    for (int i = currentIndex; i < entries.Count; i++)
                    {
                        retainedEntries!.Add(entries[i]);
                    }

                    currentIndex = entries.Count;
                }

                break;
            }

            if (entry.Offset < expectedOffset)
            {
                int skip = (int)(expectedOffset - entry.Offset);
                if (skip >= entry.Data.Length)
                {
                    remainingBufferedBytes -= entry.Data.Length;
                    currentIndex++;
                    continue;
                }

                entry = new Entry(expectedOffset, entry.Data[skip..]);
            }

            int bytesToCopy = Math.Min(entry.Data.Length, destination.Length - destinationIndex);
            entry.Data.AsSpan(0, bytesToCopy).CopyTo(destination[destinationIndex..]);
            destinationIndex += bytesToCopy;
            expectedOffset += (ulong)bytesToCopy;
            remainingBufferedBytes -= bytesToCopy;

            if (!consume)
            {
                currentIndex++;
                if (bytesToCopy < entry.Data.Length)
                {
                    break;
                }

                continue;
            }

            if (bytesToCopy == entry.Data.Length)
            {
                currentIndex++;
                continue;
            }

            retainedEntries!.Add(new Entry(entry.Offset + (ulong)bytesToCopy, entry.Data[bytesToCopy..]));
            currentIndex++;

            for (int i = currentIndex; i < entries.Count; i++)
            {
                retainedEntries.Add(entries[i]);
            }

            currentIndex = entries.Count;
            break;
        }

        if (destinationIndex == 0)
        {
            return false;
        }

        if (consume)
        {
            if (currentIndex < entries.Count)
            {
                for (int i = currentIndex; i < entries.Count; i++)
                {
                    retainedEntries!.Add(entries[i]);
                }
            }

            entries.Clear();
            entries.AddRange(retainedEntries!);
            bufferedBytes = remainingBufferedBytes;
            nextReadOffset = expectedOffset;
        }

        bytesWritten = destinationIndex;
        return true;
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
        internal ulong End => Offset + (ulong)Data.Length;
    }
}
