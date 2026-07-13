// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

using System.Diagnostics.CodeAnalysis;
using System.Runtime.ExceptionServices;

public sealed class QuicStreamReadLifecycleTests
{
    [Fact]
    public async Task ReadAsync_AlreadyBufferedDataReturnsExactBytes()
    {
        byte[] payload = [0x48, 0x45, 0x41, 0x44, 0x45, 0x52, 0x53];
        using QuicStream stream = CreateReadableStream(payload, fin: false);

        byte[] destination = new byte[payload.Length];
        int bytesRead = await stream.ReadAsync(destination, 0, destination.Length);

        Assert.Equal(payload.Length, bytesRead);
        Assert.True(payload.AsSpan().SequenceEqual(destination));
    }

    [Fact]
    public async Task ReadAsyncMemory_AlreadyBufferedDataReturnsExactBytes()
    {
        byte[] payload = [0x58, 0x59, 0x5A];
        using QuicStream stream = CreateReadableStream(payload, fin: false);

        byte[] destination = new byte[payload.Length];
        int bytesRead = await stream.ReadAsync(destination.AsMemory());

        Assert.Equal(payload.Length, bytesRead);
        Assert.True(payload.AsSpan().SequenceEqual(destination));
    }

    [Fact]
    public async Task ReadAsync_PartialReadsPreserveUnreadTailAndOrder()
    {
        using QuicStream stream = CreateReadableStream([0x10, 0x11, 0x12, 0x13, 0x14], fin: false);

        byte[] firstRead = new byte[2];
        int firstBytesRead = await stream.ReadAsync(firstRead, 0, firstRead.Length);

        byte[] secondRead = new byte[3];
        int secondBytesRead = await stream.ReadAsync(secondRead, 0, secondRead.Length);

        Assert.Equal(2, firstBytesRead);
        Assert.True(((ReadOnlySpan<byte>)[0x10, 0x11]).SequenceEqual(firstRead));
        Assert.Equal(3, secondBytesRead);
        Assert.True(((ReadOnlySpan<byte>)[0x12, 0x13, 0x14]).SequenceEqual(secondRead));
    }

    [Fact]
    public async Task ReadAsync_ExactReadThroughFinThenReadAfterFinReturnsZero()
    {
        byte[] payload = [0x21, 0x22, 0x23];
        using QuicStream stream = CreateReadableStream(payload, fin: true);

        byte[] destination = new byte[payload.Length];
        int bytesRead = await stream.ReadAsync(destination, 0, destination.Length);
        int eofBytesRead = await stream.ReadAsync(destination, 0, destination.Length);

        Assert.Equal(payload.Length, bytesRead);
        Assert.True(payload.AsSpan().SequenceEqual(destination));
        Assert.Equal(0, eofBytesRead);
        Assert.True(stream.ReadsClosed.IsCompletedSuccessfully);
    }

    [Fact]
    public async Task ReadAsync_ZeroLengthReadReturnsZeroAndLeavesBufferedBytes()
    {
        byte[] payload = [0x31, 0x32];
        using QuicStream stream = CreateReadableStream(payload, fin: false);

        byte[] destination = new byte[payload.Length];
        int zeroBytesRead = await stream.ReadAsync(destination, 0, 0);
        int bytesRead = await stream.ReadAsync(destination, 0, destination.Length);

        Assert.Equal(0, zeroBytesRead);
        Assert.Equal(payload.Length, bytesRead);
        Assert.True(payload.AsSpan().SequenceEqual(destination));
    }

    [Fact]
    public async Task ReadAsync_InvalidByteArrayRangeReturnsFaultedTask()
    {
        using QuicStream stream = CreateReadableStream([0x35], fin: false);

        Task<int> readTask = stream.ReadAsync(new byte[1], 0, 2);

        Assert.True(readTask.IsFaulted);
        await Assert.ThrowsAsync<ArgumentException>(async () => await readTask);
    }

    [Fact]
    public async Task ReadAsync_CanceledByteArrayReadReturnsCanceledTask()
    {
        using QuicStream stream = CreateReadableStream([0x36], fin: false);
        using CancellationTokenSource cancellation = new();
        await cancellation.CancelAsync();

        Task<int> readTask = stream.ReadAsync(new byte[1], 0, 1, cancellation.Token);

        Assert.True(readTask.IsCanceled);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await readTask);
    }

    [Fact]
    public async Task ReadAsync_WaitsWhenNoDataIsAvailable()
    {
        using QuicStream stream = CreateReadableStream();

        byte[] destination = new byte[1];
        using CancellationTokenSource cancellation = new();
        Task<int> readTask = stream.ReadAsync(destination.AsMemory(), cancellation.Token).AsTask();

        await AssertPendingAsync(readTask);

        await cancellation.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await readTask);
    }

    [Fact]
    public async Task ReadAsync_WaitingReadCompletesWithExactBytesWhenDataArrives()
    {
        using QuicStream stream = CreateReadableStream();

        byte[] destination = new byte[3];
        Task<int> readTask = stream.ReadAsync(destination.AsMemory()).AsTask();
        await AssertPendingAsync(readTask);

        InjectStreamData(stream, [0x51, 0x52, 0x53], offset: 0, fin: false);

        Assert.Equal(3, await readTask);
        Assert.True(((ReadOnlySpan<byte>)[0x51, 0x52, 0x53]).SequenceEqual(destination));
    }

    [Fact]
    public async Task ReadAsync_WaitingPartialReadPreservesUnreadTail()
    {
        using QuicStream stream = CreateReadableStream();

        byte[] first = new byte[2];
        Task<int> firstRead = stream.ReadAsync(first.AsMemory()).AsTask();
        await AssertPendingAsync(firstRead);

        InjectStreamData(stream, [0x61, 0x62, 0x63, 0x64, 0x65], offset: 0, fin: false);

        Assert.Equal(2, await firstRead);
        Assert.True(((ReadOnlySpan<byte>)[0x61, 0x62]).SequenceEqual(first));

        byte[] second = new byte[3];
        int secondBytesRead = await stream.ReadAsync(second.AsMemory());

        Assert.Equal(3, secondBytesRead);
        Assert.True(((ReadOnlySpan<byte>)[0x63, 0x64, 0x65]).SequenceEqual(second));
    }

    [Fact]
    public async Task ReadAsync_MultipleReadsPreserveByteOrderAcrossWaits()
    {
        using QuicStream stream = CreateReadableStream();

        byte[] first = new byte[2];
        Task<int> firstRead = stream.ReadAsync(first.AsMemory()).AsTask();
        await AssertPendingAsync(firstRead);

        InjectStreamData(stream, [0x71, 0x72], offset: 0, fin: false);

        Assert.Equal(2, await firstRead);
        Assert.True(((ReadOnlySpan<byte>)[0x71, 0x72]).SequenceEqual(first));

        byte[] second = new byte[2];
        Task<int> secondRead = stream.ReadAsync(second.AsMemory()).AsTask();
        await AssertPendingAsync(secondRead);

        InjectStreamData(stream, [0x73, 0x74], offset: 2, fin: false);

        Assert.Equal(2, await secondRead);
        Assert.True(((ReadOnlySpan<byte>)[0x73, 0x74]).SequenceEqual(second));
    }

    [Fact]
    public async Task ReadAsync_CancellationBeforeDataArrivesPreservesCancellation()
    {
        using QuicStream stream = CreateReadableStream();

        byte[] destination = new byte[1];
        using CancellationTokenSource cancellation = new();
        Task<int> readTask = stream.ReadAsync(destination.AsMemory(), cancellation.Token).AsTask();
        await AssertPendingAsync(readTask);

        await cancellation.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await readTask);
    }

    [Fact]
    public async Task ReadAsync_RepeatedDataAvailableNotificationsCoalesceAndPreserveTheNextWakeup()
    {
        using QuicStream stream = CreateReadableStream();

        byte[] destination = new byte[1];
        Task<int> readTask = stream.ReadAsync(destination.AsMemory()).AsTask();
        await AssertPendingAsync(readTask);

        int notificationThreadId = Environment.CurrentManagedThreadId;
        int semaphoreFullExceptions = 0;
        EventHandler<FirstChanceExceptionEventArgs> handler = (_, eventArgs) =>
        {
            if (Environment.CurrentManagedThreadId == notificationThreadId
                && eventArgs.Exception is SemaphoreFullException)
            {
                Interlocked.Increment(ref semaphoreFullExceptions);
            }
        };
        AppDomain.CurrentDomain.FirstChanceException += handler;
        try
        {
            for (int index = 0; index < 16; index++)
            {
                stream.HandleRuntimeNotification(new QuicStreamNotification(QuicStreamNotificationKind.DataAvailable, null));
            }
        }
        finally
        {
            AppDomain.CurrentDomain.FirstChanceException -= handler;
        }

        Assert.Equal(0, Volatile.Read(ref semaphoreFullExceptions));
        await AssertPendingAsync(readTask);
        InjectStreamData(stream, [0x5A], offset: 0, fin: false);

        Assert.Equal(1, await readTask);
        Assert.Equal(0x5A, destination[0]);
    }

    [Fact]
    public async Task ReadAsync_CancellationAfterDataArrivesBeforeWakePreservesCancellationAndBytes()
    {
        using QuicStream stream = CreateReadableStream();

        byte[] destination = new byte[1];
        using CancellationTokenSource cancellation = new();
        Task<int> readTask = stream.ReadAsync(destination.AsMemory(), cancellation.Token).AsTask();
        await AssertPendingAsync(readTask);

        ReceiveStreamData(stream.Bookkeeping, [0x7A], offset: 0, fin: false);
        await cancellation.CancelAsync();
        stream.HandleRuntimeNotification(new QuicStreamNotification(QuicStreamNotificationKind.DataAvailable, null));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await readTask);

        int bytesRead = await stream.ReadAsync(destination.AsMemory());
        Assert.Equal(1, bytesRead);
        Assert.Equal(0x7A, destination[0]);
    }

    [Fact]
    public async Task ReadAsync_AbortWhileWaitingPreservesException()
    {
        using QuicStream stream = CreateReadableStream();

        byte[] destination = new byte[1];
        Task<int> readTask = stream.ReadAsync(destination.AsMemory()).AsTask();
        await AssertPendingAsync(readTask);

        QuicException abortException = new(QuicError.StreamAborted, 0x52, "test read abort");
        stream.HandleRuntimeNotification(new QuicStreamNotification(QuicStreamNotificationKind.ReadAborted, abortException));

        QuicException actual = await Assert.ThrowsAsync<QuicException>(async () => await readTask);
        Assert.Same(abortException, actual);
    }

    [Fact]
    public async Task ReadAsync_AbortReleasesAllWaitingReadsWithTheSameException()
    {
        using QuicStream stream = CreateReadableStream();

        Task<int> firstRead = stream.ReadAsync(new byte[1].AsMemory()).AsTask();
        Task<int> secondRead = stream.ReadAsync(new byte[1].AsMemory()).AsTask();
        await AssertPendingAsync(firstRead);
        await AssertPendingAsync(secondRead);

        QuicException abortException = new(QuicError.StreamAborted, 0x52, "test read abort");
        stream.HandleRuntimeNotification(new QuicStreamNotification(QuicStreamNotificationKind.ReadAborted, abortException));

        QuicException firstActual = await Assert.ThrowsAsync<QuicException>(async () => await firstRead);
        QuicException secondActual = await Assert.ThrowsAsync<QuicException>(async () => await secondRead);
        Assert.Same(abortException, firstActual);
        Assert.Same(abortException, secondActual);
    }

    [Fact]
    public async Task TryReadTerminalAsync_StreamAbortReturnsEndOfStreamForObserverDrain()
    {
        using QuicStream stream = CreateReadableStream();

        QuicException abortException = new(QuicError.StreamAborted, 0x52, "test read abort");
        stream.HandleRuntimeNotification(new QuicStreamNotification(QuicStreamNotificationKind.ReadAborted, abortException));

        byte[] destination = new byte[1];
        int bytesRead = await stream.TryReadTerminalAsync(destination.AsMemory(), CancellationToken.None);

        Assert.Equal(0, bytesRead);
    }

    [Fact]
    public async Task TryReadTerminalAsync_ReusesPendingCompletionAcrossDataAndCancellation()
    {
        using QuicStream stream = CreateReadableStream();

        byte[] firstDestination = new byte[1];
        ValueTask<int> firstRead = stream.TryReadTerminalAsync(firstDestination.AsMemory(), CancellationToken.None);
        Assert.False(firstRead.IsCompleted);

        InjectStreamData(stream, [0x61], offset: 0, fin: false);

        Assert.Equal(1, await firstRead);
        Assert.Equal(0x61, firstDestination[0]);

        using CancellationTokenSource cancellation = new();
        ValueTask<int> canceledRead = stream.TryReadTerminalAsync(new byte[1].AsMemory(), cancellation.Token);
        Assert.False(canceledRead.IsCompleted);
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await canceledRead);

        byte[] finalDestination = new byte[1];
        ValueTask<int> finalRead = stream.TryReadTerminalAsync(finalDestination.AsMemory(), CancellationToken.None);
        InjectStreamData(stream, [0x62], offset: 1, fin: false);

        Assert.Equal(1, await finalRead);
        Assert.Equal(0x62, finalDestination[0]);
    }

    [Fact]
    public async Task TryReadTerminalAsync_DelayedConsumptionPreservesPriorValueTaskToken()
    {
        using QuicStream stream = CreateReadableStream();

        byte[] firstDestination = new byte[1];
        ValueTask<int> firstRead = stream.TryReadTerminalAsync(firstDestination.AsMemory(), CancellationToken.None);
        InjectStreamData(stream, [0x71], offset: 0, fin: false);
        Assert.True(firstRead.IsCompleted);

        byte[] secondDestination = new byte[1];
        ValueTask<int> secondRead = stream.TryReadTerminalAsync(secondDestination.AsMemory(), CancellationToken.None);
        Assert.False(secondRead.IsCompleted);
        InjectStreamData(stream, [0x72], offset: 1, fin: false);

        Assert.Equal(1, await secondRead);
        Assert.Equal(0x72, secondDestination[0]);
        Assert.Equal(1, await firstRead);
        Assert.Equal(0x71, firstDestination[0]);
    }

    [Fact]
    public async Task TryReadTerminalAsync_DisposalCompletesPendingReadAsEndOfStream()
    {
        QuicStream stream = CreateReadableStream();
        ValueTask<int> pendingRead = stream.TryReadTerminalAsync(new byte[1].AsMemory(), CancellationToken.None);
        Assert.False(pendingRead.IsCompleted);

        stream.Dispose();

        Assert.Equal(0, await pendingRead);
    }

    [Fact]
    public async Task DisposeAsync_ReleasesPendingReadWithObjectDisposedException()
    {
        QuicStream stream = CreateReadableStream();

        byte[] destination = new byte[1];
        Task<int> readTask = stream.ReadAsync(destination.AsMemory()).AsTask();
        await AssertPendingAsync(readTask);

        await stream.DisposeAsync();

        await Assert.ThrowsAsync<ObjectDisposedException>(async () => await readTask);
        Assert.True(stream.ReadsClosed.IsCompletedSuccessfully);
        Assert.True(stream.WritesClosed.IsCompletedSuccessfully);
    }

    [Fact]
    public async Task DisposeAsync_ReleasesAllPendingReadsWithObjectDisposedException()
    {
        QuicStream stream = CreateReadableStream();

        Task<int> firstRead = stream.ReadAsync(new byte[1].AsMemory()).AsTask();
        Task<int> secondRead = stream.ReadAsync(new byte[1].AsMemory()).AsTask();
        await AssertPendingAsync(firstRead);
        await AssertPendingAsync(secondRead);

        await stream.DisposeAsync();

        await Assert.ThrowsAsync<ObjectDisposedException>(async () => await firstRead);
        await Assert.ThrowsAsync<ObjectDisposedException>(async () => await secondRead);
    }

    [Fact]
    public async Task ReadAsync_ConcurrentCancellationNotificationAndDisposalDoNotStrandWaiters()
    {
        for (int iteration = 0; iteration < 100; iteration++)
        {
            QuicStream stream = CreateReadableStream();
            using CancellationTokenSource cancellation = new();
            Task<int> cancellableRead = stream.ReadAsync(new byte[1].AsMemory(), cancellation.Token).AsTask();
            Task<int> terminalRead = stream.ReadAsync(new byte[1].AsMemory()).AsTask();
            await AssertPendingAsync(cancellableRead);
            await AssertPendingAsync(terminalRead);

            await Task.WhenAll(
                Task.Run(cancellation.Cancel),
                Task.Run(() => stream.HandleRuntimeNotification(
                    new QuicStreamNotification(QuicStreamNotificationKind.DataAvailable, null))),
                Task.Run(stream.Dispose));

            Exception? cancellationOutcome = await Record.ExceptionAsync(
                    async () => await cancellableRead)
                .WaitAsync(TimeSpan.FromSeconds(2));
            Exception? terminalOutcome = await Record.ExceptionAsync(
                    async () => await terminalRead)
                .WaitAsync(TimeSpan.FromSeconds(2));

            Assert.True(cancellationOutcome is OperationCanceledException or ObjectDisposedException);
            Assert.IsType<ObjectDisposedException>(terminalOutcome);
        }
    }

    [Fact]
    public async Task ReadAsync_FinWhileWaitingCompletesWithZeroAndClosesReads()
    {
        using QuicStream stream = CreateReadableStream();

        byte[] destination = new byte[1];
        Task<int> readTask = stream.ReadAsync(destination.AsMemory()).AsTask();
        await AssertPendingAsync(readTask);

        InjectStreamData(stream, [], offset: 0, fin: true);

        Assert.Equal(0, await readTask);
        Assert.True(stream.ReadsClosed.IsCompletedSuccessfully);
    }

    [Fact]
    public async Task ReadAsync_FinReleasesAllWaitingReadsWithEndOfStream()
    {
        using QuicStream stream = CreateReadableStream();

        Task<int> firstRead = stream.ReadAsync(new byte[1].AsMemory()).AsTask();
        Task<int> secondRead = stream.ReadAsync(new byte[1].AsMemory()).AsTask();
        await AssertPendingAsync(firstRead);
        await AssertPendingAsync(secondRead);

        InjectStreamData(stream, [], offset: 0, fin: true);

        Assert.Equal(0, await firstRead);
        Assert.Equal(0, await secondRead);
        Assert.True(stream.ReadsClosed.IsCompletedSuccessfully);
    }

    [Fact]
    public async Task ReadAsync_ReadAfterFinPreservesEndOfStream()
    {
        using QuicStream stream = CreateReadableStream();

        InjectStreamData(stream, [], offset: 0, fin: true);

        byte[] destination = new byte[1];
        Assert.Equal(0, await stream.ReadAsync(destination.AsMemory()));
        Assert.Equal(0, await stream.ReadAsync(destination.AsMemory()));
        Assert.True(stream.ReadsClosed.IsCompletedSuccessfully);
    }

    [Fact]
    public async Task ReadAsync_OnlyOneWaitingReadIsReleasedPerNotification()
    {
        using QuicStream stream = CreateReadableStream();

        byte[] first = new byte[1];
        byte[] second = new byte[1];
        Task<int> firstRead = stream.ReadAsync(first.AsMemory()).AsTask();
        Task<int> secondRead = stream.ReadAsync(second.AsMemory()).AsTask();
        await AssertPendingAsync(firstRead);
        await AssertPendingAsync(secondRead);

        InjectStreamData(stream, [0x81], offset: 0, fin: false);

        Assert.Equal(1, await firstRead);
        Assert.Equal(0x81, first[0]);
        await AssertPendingAsync(secondRead);

        InjectStreamData(stream, [0x82], offset: 1, fin: false);

        Assert.Equal(1, await secondRead);
        Assert.Equal(0x82, second[0]);
    }

    [Fact]
    public async Task ReadAsync_WaitingReadPreservesFlowControlCreditAccounting()
    {
        using QuicStream stream = CreateReadableStream(initialReceiveLimit: 8);

        byte[] destination = new byte[2];
        Task<int> readTask = stream.ReadAsync(destination.AsMemory()).AsTask();
        await AssertPendingAsync(readTask);

        InjectStreamData(stream, [0x91, 0x92], offset: 0, fin: false);

        Assert.Equal(2, await readTask);
        Assert.True(stream.Bookkeeping.TryGetStreamSnapshot(0, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(2UL, snapshot.ReadOffset);
        Assert.Equal(10UL, snapshot.ReceiveLimit);
    }

    [Fact]
    [SuppressMessage(
        "Reliability",
        "CA2022:Avoid inexact read",
        Justification = "This test verifies cancellation before payload delivery and does not consume a successful read result.")]
    public async Task ReadAsync_CanceledBeforeWaitingPreservesCancellation()
    {
        using QuicStream stream = CreateReadableStream([0x41], fin: false);

        byte[] destination = new byte[1];
        Assert.Equal(1, await stream.ReadAsync(destination, 0, destination.Length));

        using CancellationTokenSource cancellation = new();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await stream.ReadAsync(destination, 0, destination.Length, cancellation.Token));
    }

    [Fact]
    [SuppressMessage(
        "Reliability",
        "CA2022:Avoid inexact read",
        Justification = "This test verifies cancellation before payload delivery and does not consume a successful read result.")]
    public async Task ReadAsyncMemory_CanceledBeforeWaitingPreservesCancellation()
    {
        using QuicStream stream = CreateReadableStream([0x42], fin: false);

        byte[] destination = new byte[1];
        Assert.Equal(1, await stream.ReadAsync(destination.AsMemory()));

        using CancellationTokenSource cancellation = new();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await stream.ReadAsync(destination.AsMemory(), cancellation.Token));
    }

    private static QuicStream CreateReadableStream(ReadOnlySpan<byte> payload, bool fin)
    {
        QuicConnectionStreamState state = CreateServerReceiveState();
        QuicStreamFrame frame = ParseStreamFrame(streamId: 0, offset: 0, payload, fin);
        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        return new QuicStream(state, streamId: 0);
    }

    private static QuicStream CreateReadableStream(ulong initialReceiveLimit = 4096)
    {
        QuicConnectionStreamState state = CreateServerReceiveState(initialReceiveLimit);
        ReceiveStreamData(state, [], offset: 0, fin: false);
        return new QuicStream(state, streamId: 0);
    }

    private static void InjectStreamData(QuicStream stream, ReadOnlySpan<byte> payload, ulong offset, bool fin)
    {
        ReceiveStreamData(stream.Bookkeeping, payload, offset, fin);
        stream.HandleRuntimeNotification(new QuicStreamNotification(QuicStreamNotificationKind.DataAvailable, null));
    }

    private static void ReceiveStreamData(QuicConnectionStreamState state, ReadOnlySpan<byte> payload, ulong offset, bool fin)
    {
        QuicStreamFrame frame = ParseStreamFrame(streamId: 0, offset, payload, fin);
        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
    }

    private static async Task AssertPendingAsync(Task<int> readTask)
    {
        await Task.Delay(20);
        Assert.False(readTask.IsCompleted);
    }

    private static QuicConnectionStreamState CreateServerReceiveState(ulong initialReceiveLimit = 4096)
    {
        return new QuicConnectionStreamState(new QuicConnectionStreamStateOptions(
            IsServer: true,
            InitialConnectionReceiveLimit: initialReceiveLimit,
            InitialConnectionSendLimit: 4096,
            InitialIncomingBidirectionalStreamLimit: 16,
            InitialIncomingUnidirectionalStreamLimit: 16,
            InitialPeerBidirectionalStreamLimit: 16,
            InitialPeerUnidirectionalStreamLimit: 16,
            InitialLocalBidirectionalReceiveLimit: initialReceiveLimit,
            InitialPeerBidirectionalReceiveLimit: initialReceiveLimit,
            InitialPeerUnidirectionalReceiveLimit: 4096,
            InitialLocalBidirectionalSendLimit: 4096,
            InitialLocalUnidirectionalSendLimit: 4096,
            InitialPeerBidirectionalSendLimit: 4096));
    }

    private static QuicStreamFrame ParseStreamFrame(ulong streamId, ulong offset, ReadOnlySpan<byte> payload, bool fin)
    {
        byte frameType = QuicStreamFrameBits.StreamFrameTypeMinimum | QuicStreamFrameBits.LengthBitMask;
        if (offset != 0)
        {
            frameType |= QuicStreamFrameBits.OffsetBitMask;
        }

        if (fin)
        {
            frameType |= QuicStreamFrameBits.FinBitMask;
        }

        byte[] buffer = new byte[64];
        Assert.True(QuicFrameCodec.TryFormatStreamFrame(frameType, streamId, offset, payload, buffer, out int bytesWritten));
        Assert.True(QuicStreamParser.TryParseStreamFrame(buffer.AsSpan(0, bytesWritten), out QuicStreamFrame frame));
        Assert.Equal(streamId, frame.StreamId.Value);
        Assert.Equal(offset, frame.Offset);
        Assert.Equal(payload.Length, frame.StreamDataLength);
        Assert.Equal(fin, frame.IsFin);
        Assert.True(payload.SequenceEqual(frame.StreamData));
        return frame;
    }
}
