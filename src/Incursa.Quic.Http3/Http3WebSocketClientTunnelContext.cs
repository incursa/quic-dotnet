// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Security.Cryptography;
using Incursa.Qpack;

namespace Incursa.Quic.Http3;

/// <summary>
/// Provides access to an opened RFC 9220 WebSocket tunnel stream from the HTTP/3 client side.
/// </summary>
public sealed class Http3WebSocketClientTunnelContext : IAsyncDisposable
{
    private const int DefaultReadBufferSize = 4096;
    private const int MaskingKeyLength = 4;

    private readonly Http3WebSocketMessageReader reader = new(Http3EndpointRole.Client);
    private readonly Queue<Http3WebSocketMessage> pendingMessages = [];
    private readonly SemaphoreSlim writeGate = new(1, 1);
    private readonly byte[] readBuffer;

    /// <summary>
    /// Initializes a new instance of the <see cref="Http3WebSocketClientTunnelContext" /> class.
    /// </summary>
    public Http3WebSocketClientTunnelContext(
        QuicStream stream,
        int statusCode,
        IReadOnlyList<QPackFieldLine> responseHeaders)
        : this(stream, statusCode, responseHeaders, DefaultReadBufferSize)
    {
    }

    internal Http3WebSocketClientTunnelContext(
        QuicStream stream,
        int statusCode,
        IReadOnlyList<QPackFieldLine> responseHeaders,
        int readBufferSize)
    {
        Stream = stream ?? throw new ArgumentNullException(nameof(stream));
        ResponseHeaders = responseHeaders ?? throw new ArgumentNullException(nameof(responseHeaders));
        if (readBufferSize <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(readBufferSize), "The WebSocket tunnel read buffer size must be positive.");
        }

        StatusCode = statusCode;
        readBuffer = new byte[readBufferSize];
    }

    /// <summary>
    /// Gets the bidirectional HTTP/3 request stream carrying WebSocket bytes after the response headers.
    /// </summary>
    public QuicStream Stream { get; }

    /// <summary>
    /// Gets the successful Extended CONNECT response status code.
    /// </summary>
    public int StatusCode { get; }

    /// <summary>
    /// Gets the decoded Extended CONNECT response headers that opened the tunnel.
    /// </summary>
    public IReadOnlyList<QPackFieldLine> ResponseHeaders { get; }

    /// <summary>
    /// Reads the next complete server-to-client WebSocket message from the tunnel stream.
    /// </summary>
    public async ValueTask<Http3WebSocketMessage?> ReadMessageAsync(CancellationToken cancellationToken = default)
    {
        if (pendingMessages.TryDequeue(out Http3WebSocketMessage? pending))
        {
            return pending;
        }

        while (true)
        {
            int bytesRead = await Stream.ReadAsync(readBuffer, 0, readBuffer.Length, cancellationToken).ConfigureAwait(false);
            Http3WebSocketMessage[] messages = bytesRead == 0
                ? reader.Complete()
                : reader.Read(readBuffer.AsSpan(0, bytesRead));

            if (messages.Length != 0)
            {
                for (int index = 1; index < messages.Length; index++)
                {
                    pendingMessages.Enqueue(messages[index]);
                }

                return messages[0];
            }

            if (bytesRead == 0)
            {
                return null;
            }
        }
    }

    /// <summary>
    /// Writes a masked client-to-server WebSocket message on the tunnel stream.
    /// </summary>
    public async ValueTask WriteMessageAsync(
        Http3WebSocketOpcode opcode,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken = default)
    {
        await writeGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await WriteMessageCoreAsync(opcode, payload, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            writeGate.Release();
        }
    }

    /// <summary>
    /// Echoes a received ping frame as a masked pong frame.
    /// </summary>
    public async ValueTask EchoPingAsync(Http3WebSocketMessage pingMessage, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pingMessage);
        if (pingMessage.Opcode != Http3WebSocketOpcode.Ping)
        {
            throw new ArgumentException("Only WebSocket ping messages can be echoed as pong frames.", nameof(pingMessage));
        }

        await WriteMessageAsync(Http3WebSocketOpcode.Pong, pingMessage.Payload, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Writes a masked client-to-server ping frame while leaving the tunnel open for subsequent messages.
    /// </summary>
    public async ValueTask PingAsync(ReadOnlyMemory<byte> payload, CancellationToken cancellationToken = default)
    {
        await WriteMessageAsync(Http3WebSocketOpcode.Ping, payload, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Echoes a received close frame and completes the writable side of the tunnel stream.
    /// </summary>
    public async ValueTask EchoCloseAsync(Http3WebSocketMessage closeMessage, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(closeMessage);
        _ = Http3WebSocketCloseFrameParser.Parse(closeMessage);
        await writeGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await WriteMessageCoreAsync(Http3WebSocketOpcode.Close, closeMessage.Payload, cancellationToken).ConfigureAwait(false);
            await Stream.CompleteWritesAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            writeGate.Release();
        }
    }

    /// <summary>
    /// Writes an application-selected masked close frame and completes the writable side of the tunnel stream.
    /// </summary>
    public async ValueTask CloseAsync(ushort? statusCode = null, string? reason = null, CancellationToken cancellationToken = default)
    {
        byte[] payload = Http3WebSocketCloseFrameParser.FormatPayload(statusCode, reason);
        await writeGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await WriteMessageCoreAsync(Http3WebSocketOpcode.Close, payload, cancellationToken).ConfigureAwait(false);
            await Stream.CompleteWritesAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            writeGate.Release();
        }
    }

    /// <summary>
    /// Disposes the underlying tunnel stream.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        await Stream.DisposeAsync().ConfigureAwait(false);
        writeGate.Dispose();
    }

    private async ValueTask WriteMessageCoreAsync(
        Http3WebSocketOpcode opcode,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken)
    {
        byte[] maskingKey = new byte[MaskingKeyLength];
        RandomNumberGenerator.Fill(maskingKey);
        byte[] frame = Http3WebSocketFrameWriter.WriteMasked(opcode, payload.Span, maskingKey);
        await Stream.WriteAsync(frame, 0, frame.Length, cancellationToken).ConfigureAwait(false);
    }
}
