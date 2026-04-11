using System.Threading;

namespace Incursa.Quic;

/// <summary>
/// Stream facade backed by the connection stream-state seam.
/// </summary>
public sealed class QuicStream : Stream
{
    private static readonly TimeSpan PendingReadPollInterval = TimeSpan.FromMilliseconds(10);

    private readonly QuicConnectionStreamState bookkeeping;
    private readonly QuicConnectionRuntime? runtime;
    private readonly ulong streamId;
    private readonly QuicStreamType type;
    private readonly bool canRead;
    private readonly bool canWrite;
    private readonly TaskCompletionSource<object?> readsClosed = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly SemaphoreSlim writeGate = new(1, 1);
    private int disposed;

    internal QuicStream(QuicConnectionStreamState bookkeeping, ulong streamId, QuicConnectionRuntime? runtime = null)
    {
        this.bookkeeping = bookkeeping ?? throw new ArgumentNullException(nameof(bookkeeping));
        this.runtime = runtime;
        this.streamId = streamId;

        if (!bookkeeping.TryGetStreamSnapshot(streamId, out QuicConnectionStreamSnapshot snapshot))
        {
            throw new ArgumentOutOfRangeException(nameof(streamId));
        }

        type = snapshot.StreamType;
        canRead = snapshot.ReceiveState != QuicStreamReceiveState.None;
        canWrite = snapshot.SendState != QuicStreamSendState.None;

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

    public override bool CanWrite => Volatile.Read(ref disposed) == 0 && canWrite;

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
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        ValidateRange(buffer.Length, offset, count);
        return ReadCoreAsync(buffer.AsMemory(offset, count), CancellationToken.None, useAsyncWait: false).GetAwaiter().GetResult();
    }

    public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        ValidateRange(buffer.Length, offset, count);
        return await ReadCoreAsync(buffer.AsMemory(offset, count), cancellationToken, useAsyncWait: true).ConfigureAwait(false);
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        ValidateRange(buffer.Length, offset, count);
        WriteCoreAsync(buffer.AsMemory(offset, count), CancellationToken.None).GetAwaiter().GetResult();
    }

    public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        ValidateRange(buffer.Length, offset, count);
        await WriteCoreAsync(buffer.AsMemory(offset, count), cancellationToken).ConfigureAwait(false);
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
        return DisposeCoreAsync(useAsyncWait: true);
    }

    protected override void Dispose(bool disposing)
    {
        if (!disposing)
        {
            base.Dispose(disposing);
            return;
        }

        DisposeCoreAsync(useAsyncWait: false).GetAwaiter().GetResult();
    }

    private async ValueTask DisposeCoreAsync(bool useAsyncWait)
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
        {
            return;
        }

        try
        {
            if (canWrite && runtime is not null)
            {
                if (useAsyncWait)
                {
                    await writeGate.WaitAsync().ConfigureAwait(false);
                }
                else
                {
                    writeGate.WaitAsync().GetAwaiter().GetResult();
                }

                try
                {
                    if (runtime.GetStreamOperationException() is null
                        && bookkeeping.TryGetStreamSnapshot(streamId, out QuicConnectionStreamSnapshot snapshot)
                        && snapshot.SendState is QuicStreamSendState.Ready or QuicStreamSendState.Send)
                    {
                        await runtime.CompleteStreamWritesAsync(streamId).ConfigureAwait(false);
                    }
                }
                catch
                {
                    // Disposal is best-effort cleanup for this narrow slice.
                }
                finally
                {
                    writeGate.Release();
                }
            }
        }
        finally
        {
            readsClosed.TrySetResult(null);
            writeGate.Dispose();
            base.Dispose(disposing: true);
        }
    }

    private async ValueTask<int> ReadCoreAsync(Memory<byte> buffer, CancellationToken cancellationToken, bool useAsyncWait)
    {
        while (true)
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);

            if (!canRead)
            {
                throw new InvalidOperationException("This stream does not have a readable side.");
            }

            cancellationToken.ThrowIfCancellationRequested();

            Exception? runtimeException = runtime?.GetStreamOperationException();
            if (runtimeException is not null)
            {
                throw runtimeException;
            }

            if (buffer.IsEmpty)
            {
                return 0;
            }

            if (bookkeeping.TryReadStreamData(
                streamId,
                buffer.Span,
                out int bytesWritten,
                out bool completed,
                out _,
                out _,
                out QuicTransportErrorCode errorCode))
            {
                if (completed)
                {
                    readsClosed.TrySetResult(null);
                }

                return bytesWritten;
            }

            if (completed)
            {
                readsClosed.TrySetResult(null);
                return 0;
            }

            if (errorCode != default)
            {
                throw new QuicException(QuicError.TransportError, null, (long)errorCode, "The stream could not be read.");
            }

            if (useAsyncWait)
            {
                await Task.Delay(PendingReadPollInterval, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                cancellationToken.WaitHandle.WaitOne(PendingReadPollInterval);
            }
        }
    }

    private async ValueTask WriteCoreAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);

        if (!canWrite)
        {
            throw new InvalidOperationException("This stream does not have a writable side.");
        }

        if (runtime is null)
        {
            throw new NotSupportedException("Writing requires the supported connection runtime path.");
        }

        Exception? runtimeException = runtime.GetStreamOperationException();
        if (runtimeException is not null)
        {
            throw runtimeException;
        }

        if (buffer.IsEmpty)
        {
            return;
        }

        await writeGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);

            runtimeException = runtime.GetStreamOperationException();
            if (runtimeException is not null)
            {
                throw runtimeException;
            }

            await runtime.WriteStreamAsync(streamId, buffer, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            writeGate.Release();
        }
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
