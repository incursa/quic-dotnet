// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Bridges accepted RFC 9220 WebSocket tunnel binary messages to a connected TCP stream.
/// </summary>
public static class Http3WebSocketTcpForwarder
{
    private const int DefaultBufferSize = 16 * 1024;
    private const ushort NormalClosureStatusCode = 1000;
    private const ushort UnsupportedDataStatusCode = 1003;

    /// <summary>
    /// Forwards binary WebSocket tunnel messages to <paramref name="tcpStream" /> and returns TCP bytes as binary WebSocket messages.
    /// </summary>
    public static async ValueTask ForwardAsync(
        Http3WebSocketTunnelContext context,
        Stream tcpStream,
        CancellationToken cancellationToken = default)
    {
        await ForwardAsync(context, tcpStream, DefaultBufferSize, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Forwards binary WebSocket tunnel messages to <paramref name="tcpStream" /> and returns TCP bytes as binary WebSocket messages.
    /// </summary>
    public static async ValueTask ForwardAsync(
        Http3WebSocketTunnelContext context,
        Stream tcpStream,
        Http3WebSocketTcpForwarderOptions? options,
        CancellationToken cancellationToken = default)
    {
        options ??= new Http3WebSocketTcpForwarderOptions();
        await ForwardAsync(context, tcpStream, options.BufferSize, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Forwards binary WebSocket tunnel messages to <paramref name="tcpStream" /> and returns TCP bytes as binary WebSocket messages.
    /// </summary>
    public static async ValueTask ForwardAsync(
        Http3WebSocketTunnelContext context,
        Stream tcpStream,
        int bufferSize,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(tcpStream);
        if (bufferSize <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(bufferSize), "The TCP forwarding buffer size must be positive.");
        }

        using CancellationTokenSource tunnelCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        Task websocketToTcp = ForwardWebSocketToTcpAsync(context, tcpStream, tunnelCancellation.Token);
        Task tcpToWebSocket = ForwardTcpToWebSocketAsync(context, tcpStream, bufferSize, tunnelCancellation.Token);
        Task completed = await Task.WhenAny(websocketToTcp, tcpToWebSocket).ConfigureAwait(false);
        Task remaining = ReferenceEquals(completed, websocketToTcp) ? tcpToWebSocket : websocketToTcp;
        Exception? completedFailure = null;

        try
        {
            await completed.ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is not OperationCanceledException || !tunnelCancellation.IsCancellationRequested)
        {
            completedFailure = exception;
        }

        await tunnelCancellation.CancelAsync().ConfigureAwait(false);
        await AwaitExpectedCancellationAsync(remaining, tunnelCancellation.Token).ConfigureAwait(false);
        if (completedFailure is not null)
        {
            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(completedFailure).Throw();
        }
    }

    private static async Task ForwardWebSocketToTcpAsync(
        Http3WebSocketTunnelContext context,
        Stream tcpStream,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            Http3WebSocketMessage? message = await context.ReadMessageOrCloseOnProtocolErrorAsync(cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            if (message is null)
            {
                return;
            }

            if (message.Opcode == Http3WebSocketOpcode.Binary)
            {
                await tcpStream.WriteAsync(message.Payload, cancellationToken).ConfigureAwait(false);
                await tcpStream.FlushAsync(cancellationToken).ConfigureAwait(false);
                continue;
            }

            if (message.Opcode == Http3WebSocketOpcode.Ping)
            {
                await context.EchoPingAsync(message, cancellationToken).ConfigureAwait(false);
                continue;
            }

            if (message.Opcode == Http3WebSocketOpcode.Pong)
            {
                continue;
            }

            if (message.Opcode == Http3WebSocketOpcode.Close)
            {
                await context.EchoCloseAsync(message, cancellationToken).ConfigureAwait(false);
                return;
            }

            await context.CloseAsync(UnsupportedDataStatusCode, "binary required", cancellationToken).ConfigureAwait(false);
            return;
        }
    }

    private static async Task ForwardTcpToWebSocketAsync(
        Http3WebSocketTunnelContext context,
        Stream tcpStream,
        int bufferSize,
        CancellationToken cancellationToken)
    {
        byte[] buffer = new byte[bufferSize];
        while (true)
        {
            int bytesRead = await tcpStream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (bytesRead == 0)
            {
                await context.CloseAsync(NormalClosureStatusCode, "tcp closed", cancellationToken).ConfigureAwait(false);
                return;
            }

            await context.WriteMessageAsync(Http3WebSocketOpcode.Binary, buffer.AsMemory(0, bytesRead), cancellationToken)
                .ConfigureAwait(false);
        }
    }

    private static async Task AwaitExpectedCancellationAsync(Task task, CancellationToken cancellationToken)
    {
        try
        {
            await task.ConfigureAwait(false);
        }
        catch (OperationCanceledException exception) when (cancellationToken.IsCancellationRequested)
        {
            GC.KeepAlive(exception);
        }
    }
}
