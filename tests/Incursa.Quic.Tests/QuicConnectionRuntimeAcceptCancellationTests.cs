// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class QuicConnectionRuntimeAcceptCancellationTests
{
    [Fact]
    public async Task TryAcceptInboundStreamAsync_ReturnsNullWhenPendingAcceptIsCanceled()
    {
        await using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime();
        using CancellationTokenSource cancellation = new();

        Task<QuicStream?> acceptTask = runtime.TryAcceptInboundStreamAsync(cancellation.Token).AsTask();

        await cancellation.CancelAsync();

        Assert.Null(await acceptTask.WaitAsync(TimeSpan.FromSeconds(5)));
    }

    [Fact]
    public async Task AcceptInboundStreamAsync_PublicAcceptStillThrowsWhenPendingAcceptIsCanceled()
    {
        await using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime();
        using CancellationTokenSource cancellation = new();

        Task<QuicStream> acceptTask = runtime.AcceptInboundStreamAsync(cancellation.Token).AsTask();

        await cancellation.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => acceptTask.WaitAsync(TimeSpan.FromSeconds(5)));
    }
}
