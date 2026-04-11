using System.Threading;

namespace Incursa.Quic;

/// <summary>
/// Stream facade backed by the connection stream-state seam.
/// </summary>
public sealed class QuicStream : Stream
{
    private readonly QuicConnectionStreamState bookkeeping;
    private readonly ulong streamId;
    private readonly QuicStreamType type;
    private readonly bool canRead;
    private readonly TaskCompletionSource<object?> readsClosed = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int disposed;

    internal QuicStream(QuicConnectionStreamState bookkeeping, ulong streamId)
    {
        this.bookkeeping = bookkeeping ?? throw new ArgumentNullException(nameof(bookkeeping));
        this.streamId = streamId;

        if (!bookkeeping.TryGetStreamSnapshot(streamId, out QuicConnectionStreamSnapshot snapshot))
        {
            throw new ArgumentOutOfRangeException(nameof(streamId));
        }

        type = snapshot.StreamType;
        canRead = snapshot.ReceiveState != QuicStreamReceiveState.None;

        if (!canRead || snapshot.ReceiveState == QuicStreamReceiveState.DataRead)
        {
            readsClosed.TrySetResult(null);
        }
    }

    /// <summary>
    /// Gets the stream identifier.
    /// </summary>
    public long Id => unchecked((long)streamId);

    /// <summary>
    /// Gets the stream direction.
    /// </summary>
    public QuicStreamType Type => type;

    /// <summary>
    /// Gets a task that completes when the read side is closed.
    /// </summary>
    public Task ReadsClosed => readsClosed.Task;

    public override bool CanRead => Volatile.Read(ref disposed) == 0 && canRead;

    public override bool CanSeek => false;

    public override bool CanTimeout => false;

    public override bool CanWrite => false;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override int ReadTimeout
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override int WriteTimeout
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Flush()
    {
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        ValidateRange(buffer.Length, offset, count);
        return ReadCore(buffer.AsSpan(offset, count));
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        ValidateRange(buffer.Length, offset, count);
        return Task.FromResult(ReadCore(buffer.AsSpan(offset, count), cancellationToken));
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        throw new NotSupportedException("Writing is not supported by this slice.");
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        return Task.FromException(new NotSupportedException("Writing is not supported by this slice."));
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        throw new NotSupportedException();
    }

    public override void SetLength(long value)
    {
        throw new NotSupportedException();
    }

    public override ValueTask DisposeAsync()
    {
        Dispose(disposing: true);
        return ValueTask.CompletedTask;
    }

    protected override void Dispose(bool disposing)
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
        {
            return;
        }

        readsClosed.TrySetResult(null);
        base.Dispose(disposing);
    }

    private int ReadCore(Span<byte> buffer, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);

        if (!canRead)
        {
            throw new InvalidOperationException("This stream does not have a readable side.");
        }

        cancellationToken.ThrowIfCancellationRequested();

        if (buffer.IsEmpty)
        {
            return 0;
        }

        if (!bookkeeping.TryReadStreamData(
            streamId,
            buffer,
            out int bytesWritten,
            out bool completed,
            out _,
            out _,
            out QuicTransportErrorCode errorCode))
        {
            if (completed)
            {
                readsClosed.TrySetResult(null);
                return 0;
            }

            if (errorCode != default)
            {
                throw new QuicException(QuicError.TransportError, null, (long)errorCode, "The stream could not be read.");
            }

            throw new NotSupportedException("Blocking reads are not yet supported by this slice.");
        }

        if (completed)
        {
            readsClosed.TrySetResult(null);
        }

        return bytesWritten;
    }

    private static void ValidateRange(int bufferLength, int offset, int count)
    {
        if (offset < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(offset));
        }

        if (count < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(count));
        }

        if (bufferLength - offset < count)
        {
            throw new ArgumentException("The buffer offset and count exceed the available range.", nameof(count));
        }
    }
}

