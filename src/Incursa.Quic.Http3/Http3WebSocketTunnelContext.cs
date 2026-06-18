// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Provides access to an accepted RFC 9220 WebSocket tunnel stream.
/// </summary>
public sealed class Http3WebSocketTunnelContext
{
    private const int DefaultReadBufferSize = 4096;

    private readonly Http3WebSocketMessageReader reader = new(Http3EndpointRole.Server);
    private readonly Queue<Http3WebSocketMessage> pendingMessages = [];
    private readonly byte[] readBuffer;

    /// <summary>
    /// Initializes a new instance of the <see cref="Http3WebSocketTunnelContext" /> class.
    /// </summary>
    public Http3WebSocketTunnelContext(Http3Request request, QuicStream stream)
        : this(request, stream, DefaultReadBufferSize)
    {
    }

    internal Http3WebSocketTunnelContext(Http3Request request, QuicStream stream, int readBufferSize)
    {
        Request = request ?? throw new ArgumentNullException(nameof(request));
        Stream = stream ?? throw new ArgumentNullException(nameof(stream));
        if (readBufferSize <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(readBufferSize), "The WebSocket tunnel read buffer size must be positive.");
        }

        readBuffer = new byte[readBufferSize];
    }

    /// <summary>
    /// Gets the decoded Extended CONNECT request that opened the tunnel.
    /// </summary>
    public Http3Request Request { get; }

    /// <summary>
    /// Gets the bidirectional HTTP/3 request stream carrying WebSocket bytes after the response headers.
    /// </summary>
    public QuicStream Stream { get; }

    /// <summary>
    /// Reads the next complete client-to-server WebSocket message from the tunnel stream.
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
    /// Writes a server-to-client WebSocket message on the tunnel stream.
    /// </summary>
    public async ValueTask WriteMessageAsync(
        Http3WebSocketOpcode opcode,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken = default)
    {
        byte[] frame = Http3WebSocketFrameWriter.WriteUnmasked(opcode, payload.Span);
        await Stream.WriteAsync(frame, 0, frame.Length, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Echoes a received ping frame as an unmasked pong frame.
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
    /// Echoes a received close frame and completes the writable side of the tunnel stream.
    /// </summary>
    public async ValueTask EchoCloseAsync(Http3WebSocketMessage closeMessage, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(closeMessage);
        _ = Http3WebSocketCloseFrameParser.Parse(closeMessage);
        await WriteMessageAsync(Http3WebSocketOpcode.Close, closeMessage.Payload, cancellationToken).ConfigureAwait(false);
        await Stream.CompleteWritesAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Writes an application-selected close frame and completes the writable side of the tunnel stream.
    /// </summary>
    public async ValueTask CloseAsync(ushort? statusCode = null, string? reason = null, CancellationToken cancellationToken = default)
    {
        byte[] payload = Http3WebSocketCloseFrameParser.FormatPayload(statusCode, reason);
        await WriteMessageAsync(Http3WebSocketOpcode.Close, payload, cancellationToken).ConfigureAwait(false);
        await Stream.CompleteWritesAsync(cancellationToken).ConfigureAwait(false);
    }
}
