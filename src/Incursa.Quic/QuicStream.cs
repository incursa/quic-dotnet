// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Threading;

namespace Incursa.Quic;

/// <summary>
/// Stream facade backed by the connection stream-state seam.
/// </summary>
/// <remarks>
/// A QUIC stream provides ordered, reliable bytes for the application protocol. Message framing, request mapping,
/// cancellation meaning, and priority policy are application-layer responsibilities.
/// </remarks>
// CONTEXT: Read and write closure stay separate so half-closed and aborted states do not collapse
// into a single terminal flag, and the write gate serializes finalization against concurrent writes.
// SEE: CompleteWritesAsync and Abort
public sealed class QuicStream : Stream, IQuicStreamNotificationObserver
{
    private const long MaximumErrorCodeValue = (1L << 62) - 1;

    private readonly QuicConnectionStreamState bookkeeping;
    private readonly QuicConnectionRuntime? runtime;
    private readonly ulong streamId;
    private readonly QuicStreamType type;
    private readonly bool canRead;
    private readonly bool canWrite;
    private TaskCompletionSource<object?>? readsClosed;
    private TaskCompletionSource<object?>? writesClosed;
    private TaskCompletionSource<object?>? writeAborted;
    private int readsClosedCompleted;
    private int writesClosedCompleted;

    private TaskCompletionSource<object?> ReadsClosedTcs => readsClosed ??= new(TaskCreationOptions.RunContinuationsAsynchronously);
    private TaskCompletionSource<object?> WritesClosedTcs => writesClosed ??= new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly SemaphoreSlim readGate = new(0, int.MaxValue);
    private SemaphoreSlim? writeGateSignal;
    private int writeGateTaken;
    private int writeGateWaiterCount;
    private readonly long? runtimeObserverId;
    private Exception? readTerminalException;
    private Exception? writeTerminalException;
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
            CompleteReadsClosed();
        }

        if (!canWrite || snapshot.SendState is QuicStreamSendState.DataSent or QuicStreamSendState.DataRecvd or QuicStreamSendState.ResetSent or QuicStreamSendState.ResetRecvd)
        {
            CompleteWritesClosed();
        }

        if (runtime is not null)
        {
            QuicMetrics.RecordStreamOpened(runtime.TlsState.Role, streamId, type);
            runtimeObserverId = runtime.RegisterStreamObserver(streamId, this);
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
    /// Gets the connection-owned stream bookkeeping backing this stream.
    /// </summary>
    internal QuicConnectionStreamState Bookkeeping => bookkeeping;

    /// <summary>
    /// Gets the connection runtime backing this stream when it is attached to one.
    /// </summary>
    internal QuicConnectionRuntime? Runtime => runtime;

    /// <summary>
    /// Gets a task that faults when the peer aborts the write side or the connection terminates.
    /// </summary>
    internal Task WaitForWriteAbortAsync(CancellationToken cancellationToken = default)
    {
        if (writeTerminalException is Exception writeException)
        {
            return Task.FromException(writeException);
        }

        Exception? runtimeException = runtime?.GetStreamOperationException();
        if (runtimeException is not null)
        {
            return Task.FromException(runtimeException);
        }

        return GetOrCreateWriteAbortedCompletion().Task.WaitAsync(cancellationToken);
    }

    /// <summary>
    /// Gets or sets the local scheduling priority for this stream.
    /// Higher values are scheduled before lower values when pending application sends are flushed.
    /// This priority is local-only and is not exchanged on the wire.
    /// </summary>
    /// <remarks>
    /// This is a local send-scheduling hint. It does not implement HTTP/3 priority signaling and it does not
    /// guarantee peer processing order.
    /// </remarks>
    public int Priority
    {
        get
        {
            if (!bookkeeping.TryGetStreamPriority(streamId, out int priority))
            {
                throw new InvalidOperationException("The stream state is unavailable.");
            }

            return priority;
        }
        set
        {
            if (!canWrite)
            {
                throw new InvalidOperationException("This stream does not have a writable side.");
            }

            if (!bookkeeping.TrySetStreamPriority(streamId, value))
            {
                throw new InvalidOperationException("The stream state is unavailable.");
            }
        }
    }

    private bool IsReadsClosed => Volatile.Read(ref readsClosedCompleted) != 0;

    private bool IsWritesClosed => Volatile.Read(ref writesClosedCompleted) != 0;

    /// <summary>
    /// Gets a task that completes when the read side is closed.
    /// </summary>
    public Task ReadsClosed => GetReadsClosedTask();

    public Task WritesClosed => GetWritesClosedTask();

    public override bool CanRead => Volatile.Read(ref disposed) == 0 && canRead && !IsReadsClosed;

    public override bool CanSeek => false;

    public override bool CanTimeout => false;

    public override bool CanWrite => Volatile.Read(ref disposed) == 0 && canWrite && !IsWritesClosed;

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
        return ReadCoreAsync(buffer.AsMemory(offset, count), CancellationToken.None).GetAwaiter().GetResult();
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        try
        {
            ArgumentNullException.ThrowIfNull(buffer);
            ValidateRange(buffer.Length, offset, count);
            Memory<byte> readBuffer = buffer.AsMemory(offset, count);
            if (TryCompleteReadSynchronously(readBuffer, cancellationToken, out int bytesRead))
            {
                return Task.FromResult(bytesRead);
            }

            return ReadCoreAsync(readBuffer, cancellationToken).AsTask();
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return Task.FromCanceled<int>(cancellationToken);
        }
        catch (Exception ex)
        {
            return Task.FromException<int>(ex);
        }
    }

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (TryCompleteReadSynchronously(buffer, cancellationToken, out int bytesRead))
        {
            return ValueTask.FromResult(bytesRead);
        }

        return ReadCoreAsync(buffer, cancellationToken);
    }

    internal ValueTask<int> TryReadTerminalAsync(Memory<byte> buffer, CancellationToken cancellationToken)
    {
        if (TryCompleteReadSynchronously(buffer, cancellationToken, out int bytesRead, suppressTerminalException: true))
        {
            return ValueTask.FromResult(bytesRead);
        }

        return ReadCoreAsync(buffer, cancellationToken, suppressTerminalException: true);
    }

    internal bool HasExpectedTerminalRead =>
        Volatile.Read(ref disposed) != 0
        || readTerminalException is Exception readException && IsExpectedTerminalException(readException)
        || runtime is { HasTerminalStreamOperation: true };

    public override void Write(byte[] buffer, int offset, int count)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        ValidateRange(buffer.Length, offset, count);
        WriteCoreAsync(buffer.AsMemory(offset, count), CancellationToken.None).GetAwaiter().GetResult();
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        try
        {
            ArgumentNullException.ThrowIfNull(buffer);
            ValidateRange(buffer.Length, offset, count);
            return WriteCoreAsync(buffer.AsMemory(offset, count), cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return Task.FromCanceled(cancellationToken);
        }
        catch (Exception ex)
        {
            return Task.FromException(ex);
        }
    }

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        return new ValueTask(WriteCoreAsync(buffer, cancellationToken));
    }

    internal async ValueTask WriteFinalAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        ValidateRange(buffer.Length, offset, count);
        await WriteFinalCoreAsync(buffer.AsMemory(offset, count), cancellationToken).ConfigureAwait(false);
    }

    internal async ValueTask WriteFinalAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken)
    {
        await WriteFinalCoreAsync(buffer, cancellationToken).ConfigureAwait(false);
    }

    internal ValueTask<bool> TryWriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken)
    {
        return TryWriteCoreAsync(buffer, finishWrites: false, cancellationToken);
    }

    internal ValueTask<bool> TryWriteFinalAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken)
    {
        return TryWriteCoreAsync(buffer, finishWrites: true, cancellationToken);
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        throw new NotSupportedException();
    }

    public override void SetLength(long value)
    {
        throw new NotSupportedException();
    }

    public void Abort(QuicAbortDirection abortDirection, long errorCode)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        ValidateErrorCode(errorCode);

        bool abortRead = (abortDirection & QuicAbortDirection.Read) != 0;
        bool abortWrite = (abortDirection & QuicAbortDirection.Write) != 0;

        if (abortRead && abortWrite)
        {
            if (!canRead || !canWrite)
            {
                throw new InvalidOperationException("This stream does not support combined read/write aborts.");
            }

            if (runtime is null)
            {
                throw new NotSupportedException("Aborting both sides requires the supported connection runtime path.");
            }

            if (!IsReadsClosed)
            {
                runtime.AbortStreamReadsAsync(streamId, checked((ulong)errorCode)).GetAwaiter().GetResult();
            }

            if (!IsWritesClosed)
            {
                runtime.AbortStreamWritesAsync(streamId, checked((ulong)errorCode)).GetAwaiter().GetResult();
            }

            return;
        }

        if (!abortRead && !abortWrite)
        {
            throw new ArgumentOutOfRangeException(nameof(abortDirection));
        }

        if (abortRead)
        {
            if (!canRead)
            {
                throw new InvalidOperationException("This stream does not have a readable side.");
            }

            if (IsReadsClosed)
            {
                return;
            }

            if (runtime is null)
            {
                throw new NotSupportedException("Aborting reads requires the supported connection runtime path.");
            }

            runtime.AbortStreamReadsAsync(streamId, checked((ulong)errorCode)).GetAwaiter().GetResult();
            return;
        }

        if (!canWrite)
        {
            throw new InvalidOperationException("This stream does not have a writable side.");
        }

        if (IsWritesClosed)
        {
            return;
        }

        if (runtime is null)
        {
            throw new NotSupportedException("Aborting writes requires the supported connection runtime path.");
        }

        runtime.AbortStreamWritesAsync(streamId, checked((ulong)errorCode)).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Completes the writable side of the stream without closing the readable side.
    /// </summary>
    public async ValueTask CompleteWritesAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);

        if (!canWrite)
        {
            throw new InvalidOperationException("This stream does not have a writable side.");
        }

        if (IsWritesClosed)
        {
            return;
        }

        if (runtime is null)
        {
            throw new NotSupportedException("Completing writes requires the supported connection runtime path.");
        }

        await WaitForWriteGateAsync(cancellationToken).ConfigureAwait(false);

        try
        {
            if (runtime.GetStreamOperationException() is Exception runtimeException)
            {
                throw runtimeException;
            }

            if (!bookkeeping.TryGetStreamSnapshot(streamId, out QuicConnectionStreamSnapshot snapshot))
            {
                throw new InvalidOperationException("The stream state is unavailable.");
            }

            if (snapshot.SendState is not (QuicStreamSendState.Ready or QuicStreamSendState.Send))
            {
                CompleteWritesClosed();
                return;
            }

            await runtime.CompleteStreamWritesAsync(streamId, cancellationToken).ConfigureAwait(false);
            CompleteWritesClosed();
            runtime.TryQueueStreamCapacityRelease(streamId);
        }
        finally
        {
            ReleaseWriteGate();
        }
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
            if (runtime is not null && runtimeObserverId.HasValue)
            {
                runtime.UnregisterStreamObserver(streamId, runtimeObserverId.Value);
            }

            if (canWrite && runtime is not null)
            {
                if (useAsyncWait)
                {
                    await WaitForWriteGateAsync().ConfigureAwait(false);
                }
                else
                {
                    WaitForWriteGateAsync().GetAwaiter().GetResult();
                }

                try
                {
                    if (!runtime.HasTerminalStreamOperation
                        && bookkeeping.TryGetStreamSnapshot(streamId, out QuicConnectionStreamSnapshot snapshot)
                        && snapshot.SendState is QuicStreamSendState.Ready or QuicStreamSendState.Send)
                    {
                        if (await runtime.TryCompleteStreamWritesAsync(streamId).ConfigureAwait(false))
                        {
                            CompleteWritesClosed();
                            runtime.TryQueueStreamCapacityRelease(streamId);
                        }
                    }
                }
                catch
                {
                    // Disposal is best-effort cleanup for this narrow slice.
                }
                finally
                {
                    ReleaseWriteGate();
                }
            }
        }
        finally
        {
            if (runtime is not null)
            {
                QuicMetrics.RecordStreamClosed(runtime.TlsState.Role, streamId, type);
            }

            CompleteReadsClosed();
            CompleteWritesClosed();
            readGate.Release();
            readGate.Dispose();
            writeGateSignal?.Dispose();
            base.Dispose(disposing: true);
        }
    }

    private async ValueTask<int> ReadCoreAsync(
        Memory<byte> buffer,
        CancellationToken cancellationToken,
        bool suppressTerminalException = false)
    {
        while (true)
        {
            if (TryCompleteReadSynchronously(buffer, cancellationToken, out int bytesWritten, suppressTerminalException))
            {
                return bytesWritten;
            }

            await readGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    private bool TryCompleteReadSynchronously(
        Memory<byte> buffer,
        CancellationToken cancellationToken,
        out int bytesRead,
        bool suppressTerminalException = false)
    {
        bytesRead = 0;
        if (Volatile.Read(ref disposed) != 0)
        {
            if (suppressTerminalException)
            {
                return true;
            }

            throw new ObjectDisposedException(GetType().FullName);
        }

        if (!canRead)
        {
            throw new InvalidOperationException("This stream does not have a readable side.");
        }

        cancellationToken.ThrowIfCancellationRequested();

        if (readTerminalException is Exception readException)
        {
            if (suppressTerminalException && IsExpectedTerminalException(readException))
            {
                return true;
            }

            throw readException;
        }

        if (suppressTerminalException && runtime is { HasTerminalStreamOperation: true })
        {
            return true;
        }

        Exception? runtimeException = runtime?.GetStreamOperationException();
        if (runtimeException is not null)
        {
            if (suppressTerminalException && IsExpectedTerminalException(runtimeException))
            {
                return true;
            }

            throw runtimeException;
        }

        if (buffer.IsEmpty)
        {
            return true;
        }

        if (bookkeeping.TryReadStreamData(
            streamId,
            buffer.Span,
            out int bytesWritten,
            out bool completed,
            out QuicMaxDataFrame maxDataFrame,
            out QuicMaxStreamDataFrame maxStreamDataFrame,
            out QuicTransportErrorCode errorCode))
        {
            if (bytesWritten > 0)
            {
                QuicMaxDataFrame? maxDataUpdate = maxDataFrame.MaximumData != 0 ? maxDataFrame : null;
                QuicMaxStreamDataFrame? maxStreamDataUpdate = maxStreamDataFrame.MaximumStreamData != 0
                    ? maxStreamDataFrame
                    : null;

                runtime?.TryQueueFlowControlCreditUpdate(maxDataUpdate, maxStreamDataUpdate);
            }

            if (completed)
            {
                CompleteReadsClosed();
                runtime?.TryQueueStreamCapacityRelease(streamId);
            }

            bytesRead = bytesWritten;
            return true;
        }

        if (completed)
        {
            CompleteReadsClosed();
            runtime?.TryQueueStreamCapacityRelease(streamId);
            return true;
        }

        if (TryCreateReadAbortException(out Exception? readAbortException))
        {
            runtime?.TryQueueStreamCapacityRelease(streamId);
            throw readAbortException!;
        }

        if (errorCode != default)
        {
            throw new QuicException(QuicError.TransportError, null, (long)errorCode, "The stream could not be read.");
        }

        return false;
    }

    private static bool IsExpectedTerminalException(Exception exception)
    {
        if (exception is ObjectDisposedException)
        {
            return true;
        }

        return exception is QuicException
        {
            QuicError: QuicError.ConnectionAborted
                or QuicError.ConnectionIdle
                or QuicError.ConnectionTimeout
                or QuicError.OperationAborted,
        };
    }

    private async Task WriteCoreAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken)
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

        if (writeTerminalException is Exception writeException)
        {
            throw writeException;
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

        await WaitForWriteGateAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);

            runtimeException = runtime.GetStreamOperationException();
            if (runtimeException is not null)
            {
                throw runtimeException;
            }

            if (writeTerminalException is Exception completedWriteException)
            {
                throw completedWriteException;
            }

            await runtime.WriteStreamAsync(streamId, buffer, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            ReleaseWriteGate();
        }
    }

    private async ValueTask WriteFinalCoreAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken)
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

        if (writeTerminalException is Exception writeException)
        {
            throw writeException;
        }

        Exception? runtimeException = runtime.GetStreamOperationException();
        if (runtimeException is not null)
        {
            throw runtimeException;
        }

        await WaitForWriteGateAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);

            runtimeException = runtime.GetStreamOperationException();
            if (runtimeException is not null)
            {
                throw runtimeException;
            }

            if (writeTerminalException is Exception completedWriteException)
            {
                throw completedWriteException;
            }

            await runtime.WriteFinalStreamAsync(streamId, buffer, cancellationToken).ConfigureAwait(false);
            CompleteWritesClosed();
            runtime.TryQueueStreamCapacityRelease(streamId);
        }
        finally
        {
            ReleaseWriteGate();
        }
    }

    private ValueTask<bool> TryWriteCoreAsync(
        ReadOnlyMemory<byte> buffer,
        bool finishWrites,
        CancellationToken cancellationToken)
    {
        if (Volatile.Read(ref disposed) != 0)
        {
            return new ValueTask<bool>(false);
        }

        if (!canWrite)
        {
            throw new InvalidOperationException("This stream does not have a writable side.");
        }

        if (runtime is null)
        {
            throw new NotSupportedException("Writing requires the supported connection runtime path.");
        }

        if (writeTerminalException is not null || runtime.HasTerminalStreamOperation)
        {
            return new ValueTask<bool>(false);
        }

        if (buffer.IsEmpty && !finishWrites)
        {
            return new ValueTask<bool>(true);
        }

        ValueTask gateWait = WaitForWriteGateAsync(cancellationToken);
        if (!gateWait.IsCompletedSuccessfully)
        {
            return TryWriteCoreAfterGateWaitAsync(gateWait, buffer, finishWrites, cancellationToken);
        }

        gateWait.GetAwaiter().GetResult();
        return TryWriteCoreAfterGate(buffer, finishWrites, cancellationToken);
    }

    private async ValueTask<bool> TryWriteCoreAfterGateWaitAsync(
        ValueTask gateWait,
        ReadOnlyMemory<byte> buffer,
        bool finishWrites,
        CancellationToken cancellationToken)
    {
        await gateWait.ConfigureAwait(false);
        return await TryWriteCoreAfterGate(buffer, finishWrites, cancellationToken).ConfigureAwait(false);
    }

    private ValueTask<bool> TryWriteCoreAfterGate(
        ReadOnlyMemory<byte> buffer,
        bool finishWrites,
        CancellationToken cancellationToken)
    {
        try
        {
            if (Volatile.Read(ref disposed) != 0)
            {
                ReleaseWriteGate();
                return new ValueTask<bool>(false);
            }

            QuicConnectionRuntime currentRuntime = runtime!;
            if (writeTerminalException is not null || currentRuntime.HasTerminalStreamOperation)
            {
                ReleaseWriteGate();
                return new ValueTask<bool>(false);
            }

            ValueTask<bool> writeTask = finishWrites
                ? currentRuntime.TryWriteFinalStreamAsync(streamId, buffer, cancellationToken)
                : currentRuntime.TryWriteStreamAsync(streamId, buffer, cancellationToken);
            if (!writeTask.IsCompletedSuccessfully)
            {
                return TryWriteCoreAfterRuntimeWriteAsync(writeTask, finishWrites);
            }

            bool completed = writeTask.GetAwaiter().GetResult();
            if (!completed)
            {
                ReleaseWriteGate();
                return new ValueTask<bool>(false);
            }

            if (finishWrites)
            {
                CompleteWritesClosed();
                currentRuntime.TryQueueStreamCapacityRelease(streamId);
            }

            ReleaseWriteGate();
            return new ValueTask<bool>(true);
        }
        catch
        {
            ReleaseWriteGate();
            throw;
        }
    }

    private async ValueTask<bool> TryWriteCoreAfterRuntimeWriteAsync(
        ValueTask<bool> writeTask,
        bool finishWrites)
    {
        try
        {
            bool completed = await writeTask.ConfigureAwait(false);
            if (!completed)
            {
                return false;
            }

            if (finishWrites)
            {
                CompleteWritesClosed();
                runtime!.TryQueueStreamCapacityRelease(streamId);
            }

            return true;
        }
        finally
        {
            ReleaseWriteGate();
        }
    }

    private ValueTask WaitForWriteGateAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (Interlocked.CompareExchange(ref writeGateTaken, 1, 0) == 0)
        {
            return ValueTask.CompletedTask;
        }

        return WaitForWriteGateSlowAsync(cancellationToken);
    }

    private async ValueTask WaitForWriteGateSlowAsync(CancellationToken cancellationToken)
    {
        SemaphoreSlim signal = LazyInitializer.EnsureInitialized(
            ref writeGateSignal,
            static () => new SemaphoreSlim(0));

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Interlocked.Increment(ref writeGateWaiterCount);
            try
            {
                if (Interlocked.CompareExchange(ref writeGateTaken, 1, 0) == 0)
                {
                    return;
                }

                await signal.WaitAsync(cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                Interlocked.Decrement(ref writeGateWaiterCount);
            }

            if (Interlocked.CompareExchange(ref writeGateTaken, 1, 0) == 0)
            {
                return;
            }
        }
    }

    private void ReleaseWriteGate()
    {
        Volatile.Write(ref writeGateTaken, 0);
        if (Volatile.Read(ref writeGateWaiterCount) > 0)
        {
            Volatile.Read(ref writeGateSignal)?.Release();
        }
    }

    internal void HandleRuntimeNotification(QuicStreamNotification notification)
    {
        switch (notification.Kind)
        {
            case QuicStreamNotificationKind.ReadAborted:
                CompleteReadsClosed(notification.Exception!);
                readGate.Release();
                runtime?.TryQueueStreamCapacityRelease(streamId);
                break;
            case QuicStreamNotificationKind.WriteAborted:
                writeAborted?.TrySetException(notification.Exception!);
                CompleteWritesClosed(notification.Exception!);
                runtime?.TryQueueStreamCapacityRelease(streamId);
                break;
            case QuicStreamNotificationKind.ConnectionTerminated:
                if (canRead && !IsReadsClosed)
                {
                    CompleteReadsClosed(notification.Exception!);
                    readGate.Release();
                }

                if (canWrite && !IsWritesClosed)
                {
                    CompleteWritesClosed(notification.Exception!);
                }

                if (writeAborted is TaskCompletionSource<object?> writeAbortedCompletion
                    && !writeAbortedCompletion.Task.IsCompleted)
                {
                    writeTerminalException ??= notification.Exception;
                    writeAbortedCompletion.TrySetException(notification.Exception!);
                }

                break;
            case QuicStreamNotificationKind.DataAvailable:
                readGate.Release();
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(notification));
        }
    }

    private bool TryCreateReadAbortException(out Exception? exception)
    {
        exception = null;
        if (!bookkeeping.TryGetStreamSnapshot(streamId, out QuicConnectionStreamSnapshot snapshot)
            || snapshot.ReceiveState is not QuicStreamReceiveState.ResetRecvd and not QuicStreamReceiveState.ResetRead)
        {
            return false;
        }

        if (!snapshot.HasReceiveAbortErrorCode)
        {
            return false;
        }

        bookkeeping.TryAcknowledgeReset(streamId);
        exception = readTerminalException ??= new QuicException(
            QuicError.StreamAborted,
            checked((long)snapshot.ReceiveAbortErrorCode),
            "The peer aborted the stream.");
        CompleteReadsClosed(exception);
        return true;
    }

    private TaskCompletionSource<object?> GetOrCreateWriteAbortedCompletion()
    {
        TaskCompletionSource<object?>? current = Volatile.Read(ref writeAborted);
        if (current is not null)
        {
            return current;
        }

        TaskCompletionSource<object?> created = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource<object?>? existing = Interlocked.CompareExchange(ref writeAborted, created, null);
        return existing ?? created;
    }

    private Task GetReadsClosedTask()
    {
        if (IsReadsClosed)
        {
            return readTerminalException is Exception exception
                ? Task.FromException(exception)
                : Task.CompletedTask;
        }

        TaskCompletionSource<object?> completion = ReadsClosedTcs;
        if (IsReadsClosed)
        {
            CompleteReadsClosed(readTerminalException);
        }

        return completion.Task;
    }

    private Task GetWritesClosedTask()
    {
        if (IsWritesClosed)
        {
            return writeTerminalException is Exception exception
                ? Task.FromException(exception)
                : Task.CompletedTask;
        }

        TaskCompletionSource<object?> completion = WritesClosedTcs;
        if (IsWritesClosed)
        {
            CompleteWritesClosed(writeTerminalException);
        }

        return completion.Task;
    }

    private void CompleteReadsClosed(Exception? exception = null)
    {
        if (exception is not null)
        {
            readTerminalException ??= exception;
        }

        Volatile.Write(ref readsClosedCompleted, 1);
        TaskCompletionSource<object?>? completion = Volatile.Read(ref readsClosed);
        if (completion is null)
        {
            return;
        }

        if (exception is not null)
        {
            completion.TrySetException(exception);
        }
        else
        {
            completion.TrySetResult(null);
        }
    }

    private void CompleteWritesClosed(Exception? exception = null)
    {
        if (exception is not null)
        {
            writeTerminalException ??= exception;
        }

        Volatile.Write(ref writesClosedCompleted, 1);
        TaskCompletionSource<object?>? completion = Volatile.Read(ref writesClosed);
        if (completion is null)
        {
            return;
        }

        if (exception is not null)
        {
            completion.TrySetException(exception);
        }
        else
        {
            completion.TrySetResult(null);
        }
    }

    private static void ValidateErrorCode(long errorCode)
    {
        if (errorCode < 0 || errorCode > MaximumErrorCodeValue)
        {
            throw new ArgumentOutOfRangeException(nameof(errorCode));
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

    void IQuicStreamNotificationObserver.OnStreamNotification(QuicStreamNotification notification)
        => HandleRuntimeNotification(notification);
}
