// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Text;
using System.Net.Security;
using Incursa.Qpack;

namespace Incursa.Quic.Http3;

/// <summary>
/// Minimal HTTP/3 server over the repository QUIC transport.
/// </summary>
public sealed class Http3Server : IAsyncDisposable
{
    // CONTEXT: Response write chunking
    // SEE: spec:REQ-QUIC-RFC9114-S4-0002
    // SEE: spec:REQ-QUIC-RFC9114-S9-0001
    // SEE: code:src/Incursa.Quic.Http3/Http3FrameWriter.cs#WriteFrame
    // SEE: code:src/Incursa.Quic.Http3/Http3Server.cs#WriteFinalFrameBytesAsync
    // Keep the HTTP/3 DATA payload and QUIC write boundaries aligned so each
    // frame payload is submitted without four separate transport writes.
    private const int ResponseDataFrameChunkSize = 16 * 1024;
    private const int ResponseWriteChunkSize = ResponseDataFrameChunkSize;
    private const int MaximumCachedCompleteResponseBytes = 2 * 1024 * 1024;
    private const int FieldSectionRequiredInsertCountPrefixBits = 8;
    private const int FieldSectionBasePrefixBits = 7;
    private const int MaxWebSocketControlPayloadLength = 125;
    private const int IndexedFieldPrefixBits = 6;
    private const byte StaticIndexedFieldPrefix = 0xC0;
    private const int StaticNameReferencePrefixBits = 4;
    private const byte LiteralWithStaticNameReferencePrefix = 0x50;
    private const int LiteralNamePrefixBits = 4;
    private const byte LiteralWithLiteralNamePrefix = 0x20;
    private const int StringLiteralPrefixBits = 8;
    private const int StatusStaticNameIndex = 24;
    private const int QPackIntegerMaxPrefixBitCount = 8;
    private const ulong QPackIntegerMaxValue = 0x3FFF_FFFF_FFFF_FFFFUL;
    private const byte QPackIntegerContinuationThreshold = 0x80;
    private const int MinimumResponseStatusCode = 100;
    private const int MaximumResponseStatusCode = 999;

    private static readonly string[] ResponseStatusCodeStrings = CreateResponseStatusCodeStrings();
    private static readonly byte[] EmptyDataFrame = Http3FrameWriter.WriteData(ReadOnlySpan<byte>.Empty);
    private static readonly byte[] ResponseDataFrameChunkDataFrameHeader =
        WriteFrameHeader((ulong)Http3FrameType.Data, ResponseDataFrameChunkSize);
    private const byte QPackIntegerContinuationValueMask = 0x7F;
    private const byte QPackIntegerContinuationFlag = 0x80;
    private const int QPackIntegerContinuationShift = 7;
    private static readonly Encoding HeaderTextEncoding = Encoding.Latin1;
    private static readonly Dictionary<QPackFieldLine, int> StaticFieldLineIndexes = BuildStaticFieldLineIndexes();
    private static readonly Dictionary<string, int> StaticNameIndexes = BuildStaticNameIndexes();

    private readonly QuicListener listener;
    private readonly IHttp3RequestHandler handler;
    private readonly Http3Settings localSettings;
    private readonly int readBufferSize;
    private readonly IHttp3DiagnosticsSink? diagnosticsSink;
    private readonly IHttp3WebSocketHandler? webSocketHandler;
    private readonly Func<Http3Request, IEnumerable<QPackFieldLine>>? webSocketAcceptResponseHeadersSelector;
    private readonly TimeSpan? webSocketKeepAliveInterval;
    private readonly byte[] webSocketKeepAlivePayload;
    private readonly ushort webSocketHandlerExceptionCloseStatusCode;
    private readonly string? webSocketHandlerExceptionCloseReason;
    private readonly Func<Exception, Http3WebSocketClosePolicy?>? webSocketHandlerExceptionClosePolicySelector;
    // CONTEXT: Server shutdown ownership
    // SEE: code:src/Incursa.Quic.Http3/Http3Server.cs#ServeAsync
    // SEE: code:src/Incursa.Quic.Http3/Http3Server.cs#HandleConnectionAsync
    // SEE: code:src/Incursa.Quic.Http3/Http3Server.cs#DisposeAsync
    // The server keeps connection tasks so DisposeAsync can stop accepting new
    // connections and then await in-flight handlers instead of converting
    // normal shutdown into a failure.
    private readonly List<Task> connectionTasks = [];
    private int disposed;

    private Http3Server(QuicListener listener, IHttp3RequestHandler handler, Http3ServerOptions options)
    {
        this.listener = listener ?? throw new ArgumentNullException(nameof(listener));
        this.handler = handler ?? throw new ArgumentNullException(nameof(handler));
        ArgumentNullException.ThrowIfNull(options);
        localSettings = options.Settings ?? throw new ArgumentException("HTTP/3 server settings must not be null.", nameof(options));
        readBufferSize = options.ReadBufferSize > 0
            ? options.ReadBufferSize
            : throw new ArgumentOutOfRangeException(nameof(options), "The HTTP/3 read buffer size must be positive.");
        diagnosticsSink = options.DiagnosticsSink;
        webSocketHandler = options.WebSocketHandler;
        webSocketAcceptResponseHeadersSelector = options.WebSocketAcceptResponseHeadersSelector;
        if (options.WebSocketKeepAliveInterval is { } keepAliveInterval && keepAliveInterval <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "The WebSocket keepalive interval must be positive when configured.");
        }

        if (options.WebSocketKeepAlivePayload.Length > MaxWebSocketControlPayloadLength)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "The WebSocket keepalive payload cannot exceed 125 bytes.");
        }

        _ = Http3WebSocketCloseFrameParser.FormatPayload(
            options.WebSocketHandlerExceptionCloseStatusCode,
            options.WebSocketHandlerExceptionCloseReason);
        webSocketKeepAliveInterval = options.WebSocketKeepAliveInterval;
        webSocketKeepAlivePayload = options.WebSocketKeepAlivePayload.ToArray();
        webSocketHandlerExceptionCloseStatusCode = options.WebSocketHandlerExceptionCloseStatusCode;
        webSocketHandlerExceptionCloseReason = options.WebSocketHandlerExceptionCloseReason;
        webSocketHandlerExceptionClosePolicySelector = options.WebSocketHandlerExceptionClosePolicySelector;
    }

    /// <summary>
    /// Starts a QUIC listener that accepts ALPN h3.
    /// </summary>
    public static async ValueTask<Http3Server> ListenAsync(
        QuicListenerOptions listenerOptions,
        IHttp3RequestHandler handler,
        Http3ServerOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(listenerOptions);
        EnsureHttp3Alpn(listenerOptions);
        QuicListener listener = await QuicListener.ListenAsync(listenerOptions, cancellationToken).ConfigureAwait(false);
        return new Http3Server(listener, handler, options ?? new Http3ServerOptions());
    }

    /// <summary>
    /// Attaches the minimal HTTP/3 server layer to an already started QUIC listener.
    /// </summary>
    public static Http3Server Attach(
        QuicListener listener,
        IHttp3RequestHandler handler,
        Http3ServerOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(listener);
        ArgumentNullException.ThrowIfNull(handler);
        return new Http3Server(listener, handler, options ?? new Http3ServerOptions());
    }

    /// <summary>
    /// Accepts connections until cancellation, disposal, or a listener error stops the loop.
    /// </summary>
    public async Task ServeAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);

        while (!cancellationToken.IsCancellationRequested)
        {
            QuicConnection connection;
            try
            {
                connection = await listener.AcceptConnectionAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch (ObjectDisposedException) when (Volatile.Read(ref disposed) != 0)
            {
                break;
            }
            catch (QuicException ex)
            {
                if (IsDiagnosticEnabled(diagnosticsSink, Http3DiagnosticKind.Error))
                {
                    diagnosticsSink!.Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.Error)
                    {
                        Role = "server",
                        ErrorCode = ex.QuicError.ToString(),
                        Message = ex.Message,
                    });
                }

                continue;
            }

            Task connectionTask = HandleConnectionAsync(connection, cancellationToken);
            lock (connectionTasks)
            {
                connectionTasks.Add(connectionTask);
            }
        }
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
        {
            return;
        }

        await listener.DisposeAsync().ConfigureAwait(false);
        Task[] tasks;
        lock (connectionTasks)
        {
            tasks = [.. connectionTasks];
        }

        if (tasks.Length != 0)
        {
            await Task.WhenAll(tasks).ConfigureAwait(false);
        }
    }

    private static void EnsureHttp3Alpn(QuicListenerOptions listenerOptions)
    {
        listenerOptions.ApplicationProtocols ??= [];
        if (listenerOptions.ApplicationProtocols.Count == 0)
        {
            listenerOptions.ApplicationProtocols.Add(SslApplicationProtocol.Http3);
            return;
        }

        foreach (SslApplicationProtocol protocol in listenerOptions.ApplicationProtocols)
        {
            if (protocol.Equals(SslApplicationProtocol.Http3))
            {
                return;
            }
        }

        throw new ArgumentException("HTTP/3 requires ALPN h3 in the QUIC listener options.", nameof(listenerOptions));
    }

    private async Task HandleConnectionAsync(QuicConnection connection, CancellationToken cancellationToken)
    {
        await using (connection.ConfigureAwait(false))
        {
            try
            {
                if (IsDiagnosticEnabled(diagnosticsSink, Http3DiagnosticKind.ConnectionStarted))
                {
                    diagnosticsSink!.Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.ConnectionStarted)
                    {
                        Role = "server",
                    });
                }

                ConnectionQPackState qpackState = new(localSettings);
                QuicStream controlStream = await OpenRequiredUnidirectionalStreamsAsync(connection, cancellationToken).ConfigureAwait(false);
                await AcceptStreamsAsync(connection, controlStream, qpackState, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException exception) when (cancellationToken.IsCancellationRequested)
            {
                SuppressExpectedException(exception);
            }
            catch (ObjectDisposedException exception) when (Volatile.Read(ref disposed) != 0)
            {
                SuppressExpectedException(exception);
            }
            catch (QuicException exception)
            {
                SuppressExpectedException(exception);
            }
            catch (Exception exception)
            {
                EmitError(exception);
                throw;
            }
            finally
            {
                if (IsDiagnosticEnabled(diagnosticsSink, Http3DiagnosticKind.ConnectionClosed))
                {
                    diagnosticsSink!.Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.ConnectionClosed)
                    {
                        Role = "server",
                    });
                }
            }
        }
    }

    // CONTEXT: HTTP/3 startup order
    // SEE: spec:REQ-QUIC-RFC9114-S6-0001
    // SEE: spec:REQ-QUIC-RFC9114-S7-0001
    // SEE: code:src/Incursa.Quic.Http3/Http3Client.cs#OpenRequiredUnidirectionalStreamsAsync
    // The control stream and SETTINGS go out before the QPACK encoder/decoder
    // streams because peers require the control stream to exist first and the
    // client/server startup code mirrors this order.
    private async ValueTask<QuicStream> OpenRequiredUnidirectionalStreamsAsync(QuicConnection connection, CancellationToken cancellationToken)
    {
        QuicStream controlStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Unidirectional, cancellationToken).ConfigureAwait(false);
        byte[] initialControlStream = Http3SettingsWriter.WriteInitialControlStream(localSettings);
        await controlStream.WriteAsync(initialControlStream, 0, initialControlStream.Length, cancellationToken).ConfigureAwait(false);
        EmitStreamOpenedDiagnostic(diagnosticsSink, "server", controlStream.Id, Http3StreamKind.Control);
        EmitFrame(Http3DiagnosticKind.FrameSent, controlStream.Id, Http3FrameType.Settings, initialControlStream.Length);
        if (IsDiagnosticEnabled(diagnosticsSink, Http3DiagnosticKind.SettingsSent))
        {
            diagnosticsSink!.Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.SettingsSent)
            {
                Role = "server",
                StreamId = controlStream.Id,
            });
        }

        QuicStream qpackEncoderStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Unidirectional, cancellationToken).ConfigureAwait(false);
        await WriteStreamTypeAsync(qpackEncoderStream, Http3StreamType.QPackEncoder, cancellationToken).ConfigureAwait(false);
        EmitStreamOpenedDiagnostic(diagnosticsSink, "server", qpackEncoderStream.Id, Http3StreamKind.QPackEncoder);
        if (IsDiagnosticEnabled(diagnosticsSink, Http3DiagnosticKind.QPackInstructionSent))
        {
            diagnosticsSink!.Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.QPackInstructionSent)
            {
                Role = "server",
                StreamId = qpackEncoderStream.Id,
                StreamKind = Http3StreamKind.QPackEncoder,
                QPackInstruction = "stream_type",
            });
        }

        QuicStream qpackDecoderStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Unidirectional, cancellationToken).ConfigureAwait(false);
        await WriteStreamTypeAsync(qpackDecoderStream, Http3StreamType.QPackDecoder, cancellationToken).ConfigureAwait(false);
        EmitStreamOpenedDiagnostic(diagnosticsSink, "server", qpackDecoderStream.Id, Http3StreamKind.QPackDecoder);
        if (IsDiagnosticEnabled(diagnosticsSink, Http3DiagnosticKind.QPackInstructionSent))
        {
            diagnosticsSink!.Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.QPackInstructionSent)
            {
                Role = "server",
                StreamId = qpackDecoderStream.Id,
                StreamKind = Http3StreamKind.QPackDecoder,
                QPackInstruction = "stream_type",
            });
        }

        return controlStream;
    }

    private async Task AcceptStreamsAsync(
        QuicConnection connection,
        QuicStream controlStream,
        ConnectionQPackState qpackState,
        CancellationToken cancellationToken)
    {
        Http3StreamDispatcher dispatcher = new(Http3EndpointRole.Server);
        object dispatcherGate = new();

        while (!cancellationToken.IsCancellationRequested)
        {
            QuicStream? stream = await connection.TryAcceptInboundStreamAsync(cancellationToken).ConfigureAwait(false);
            if (stream is null)
            {
                return;
            }

            Http3StreamKind streamKind = stream.Type == QuicStreamType.Bidirectional
                ? Http3StreamKind.Request
                : Http3StreamKind.Unknown;
            if (stream.Type == QuicStreamType.Bidirectional)
            {
                lock (dispatcherGate)
                {
                    dispatcher.RegisterBidirectionalStreamState(checked((ulong)stream.Id));
                }
            }

            EmitStreamOpenedDiagnostic(diagnosticsSink, "server", stream.Id, streamKind);
            if (stream.Type == QuicStreamType.Bidirectional)
            {
                _ = HandleRequestStreamAsync(connection, stream, controlStream, dispatcher, dispatcherGate, qpackState, cancellationToken);
            }
            else
            {
                _ = ObservePeerUnidirectionalStreamAsync(connection, stream, dispatcher, dispatcherGate, qpackState, cancellationToken);
            }
        }
    }

    private async Task ObservePeerUnidirectionalStreamAsync(
        QuicConnection connection,
        QuicStream stream,
        Http3StreamDispatcher dispatcher,
        object dispatcherGate,
        ConnectionQPackState qpackState,
        CancellationToken cancellationToken)
    {
        await using (stream.ConfigureAwait(false))
        {
            byte[] buffer = QuicBufferPool.RentBytes(readBufferSize);
            Http3StreamKind streamKind = Http3StreamKind.Unknown;
            try
            {
                lock (dispatcherGate)
                {
                    dispatcher.RegisterUnidirectionalStreamState(checked((ulong)stream.Id));
                }

                while (true)
                {
                    int bytesRead = await stream.TryReadTerminalAsync(buffer.AsMemory(0, buffer.Length), cancellationToken).ConfigureAwait(false);
                    if (bytesRead == 0)
                    {
                        lock (dispatcherGate)
                        {
                            dispatcher.TryReceiveUnidirectionalStreamTypeBytes(
                                checked((ulong)stream.Id),
                                ReadOnlySpan<byte>.Empty,
                                out _,
                                out _,
                                endOfStream: true);
                        }

                        return;
                    }

                    Http3StreamInfo streamInfo;
                    int bytesConsumed;
                    bool streamTypeKnown;
                    lock (dispatcherGate)
                    {
                        streamTypeKnown = dispatcher.TryReceiveUnidirectionalStreamTypeBytes(
                            checked((ulong)stream.Id),
                            buffer.AsSpan(0, bytesRead),
                            out streamInfo,
                            out bytesConsumed);
                    }

                    if (!streamTypeKnown)
                    {
                        continue;
                    }

                    streamKind = streamInfo.Kind;
                    EmitStreamOpenedDiagnostic(diagnosticsSink, "server", stream.Id, streamKind);

                    ReadOnlyMemory<byte> initialPayload = buffer.AsMemory(bytesConsumed, bytesRead - bytesConsumed);
                    await ObservePeerUnidirectionalPayloadAsync(
                        stream,
                        dispatcher,
                        dispatcherGate,
                        qpackState,
                        streamKind,
                        initialPayload,
                        buffer,
                        cancellationToken).ConfigureAwait(false);
                    return;
                }
            }
            catch (OperationCanceledException exception) when (cancellationToken.IsCancellationRequested)
            {
                SuppressExpectedException(exception);
            }
            catch (QuicException exception)
            {
                SuppressExpectedException(exception);
            }
            catch (QPackException exception)
            {
                EmitError(exception);
                await TryCloseConnectionAsync(connection, checked((long)exception.ErrorCode), cancellationToken).ConfigureAwait(false);
            }
            catch (Http3Exception exception)
            {
                EmitError(exception);
                await TryCloseConnectionAsync(connection, checked((long)exception.ErrorCode), cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                EmitStreamClosedDiagnostic(diagnosticsSink, "server", stream.Id, streamKind);
                QuicBufferPool.ReturnBytes(buffer);
            }
        }
    }

    private async ValueTask ObservePeerUnidirectionalPayloadAsync(
        QuicStream stream,
        Http3StreamDispatcher dispatcher,
        object dispatcherGate,
        ConnectionQPackState qpackState,
        Http3StreamKind streamKind,
        ReadOnlyMemory<byte> initialPayload,
        byte[] buffer,
        CancellationToken cancellationToken)
    {
        switch (streamKind)
        {
            case Http3StreamKind.Control:
                await ObservePeerControlStreamAsync(
                    stream,
                    dispatcher,
                    dispatcherGate,
                    qpackState,
                    initialPayload,
                    buffer,
                    cancellationToken).ConfigureAwait(false);
                break;
            case Http3StreamKind.QPackEncoder:
            case Http3StreamKind.QPackDecoder:
                await DrainPeerQPackStreamAsync(stream, streamKind, initialPayload, buffer, qpackState, cancellationToken).ConfigureAwait(false);
                break;
            case Http3StreamKind.Unknown:
            case Http3StreamKind.Reserved:
                await DrainPeerUnidirectionalStreamAsync(stream, buffer, cancellationToken).ConfigureAwait(false);
                break;
            case Http3StreamKind.Push:
            case Http3StreamKind.Request:
            default:
                throw new Http3Exception(Http3ErrorCode.StreamCreationError, "The HTTP/3 unidirectional stream type is invalid for this endpoint.");
        }
    }

    private async ValueTask ObservePeerControlStreamAsync(
        QuicStream stream,
        Http3StreamDispatcher dispatcher,
        object dispatcherGate,
        ConnectionQPackState qpackState,
        ReadOnlyMemory<byte> initialPayload,
        byte[] buffer,
        CancellationToken cancellationToken)
    {
        Http3FrameReader frameReader = new();
        ProcessPeerControlBytes(frameReader, initialPayload.Span, stream.Id, dispatcher, dispatcherGate, qpackState);

        while (true)
        {
            int bytesRead = await stream.TryReadTerminalAsync(buffer.AsMemory(0, buffer.Length), cancellationToken).ConfigureAwait(false);
            if (bytesRead == 0)
            {
                if (stream.HasExpectedTerminalRead)
                {
                    return;
                }

                ProcessPeerControlFrames(frameReader.Complete(), stream.Id, dispatcher, dispatcherGate, qpackState);
                throw new Http3Exception(Http3ErrorCode.ClosedCriticalStream, "The HTTP/3 control stream was closed.");
            }

            ProcessPeerControlBytes(frameReader, buffer.AsSpan(0, bytesRead), stream.Id, dispatcher, dispatcherGate, qpackState);
        }
    }

    private async ValueTask DrainPeerQPackStreamAsync(
        QuicStream stream,
        Http3StreamKind streamKind,
        ReadOnlyMemory<byte> initialPayload,
        byte[] buffer,
        ConnectionQPackState qpackState,
        CancellationToken cancellationToken)
    {
        EmitQPackBytesReceived(stream.Id, streamKind, initialPayload.Length);
        if (streamKind == Http3StreamKind.QPackEncoder)
        {
            qpackState.ProcessPeerEncoderStreamBytes(initialPayload.Span);
        }
        else
        {
            qpackState.ProcessPeerDecoderStreamBytes(initialPayload.Span);
        }

        while (true)
        {
            int bytesRead = await stream.TryReadTerminalAsync(buffer.AsMemory(0, buffer.Length), cancellationToken).ConfigureAwait(false);
            if (bytesRead == 0)
            {
                if (stream.HasExpectedTerminalRead)
                {
                    return;
                }

                if (streamKind == Http3StreamKind.QPackEncoder)
                {
                    qpackState.CompletePeerEncoderStream();
                }
                else
                {
                    qpackState.CompletePeerDecoderStream();
                }

                throw new Http3Exception(Http3ErrorCode.ClosedCriticalStream, "The QPACK unidirectional stream was closed.");
            }

            EmitQPackBytesReceived(stream.Id, streamKind, bytesRead);
            if (streamKind == Http3StreamKind.QPackEncoder)
            {
                qpackState.ProcessPeerEncoderStreamBytes(buffer.AsSpan(0, bytesRead));
            }
            else
            {
                qpackState.ProcessPeerDecoderStreamBytes(buffer.AsSpan(0, bytesRead));
            }
        }
    }

    private static async ValueTask DrainPeerUnidirectionalStreamAsync(
        QuicStream stream,
        byte[] buffer,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            int bytesRead = await stream.TryReadTerminalAsync(buffer.AsMemory(0, buffer.Length), cancellationToken).ConfigureAwait(false);
            if (bytesRead == 0)
            {
                return;
            }
        }
    }

    private async ValueTask HandleRequestStreamAsync(
        QuicConnection connection,
        QuicStream stream,
        QuicStream controlStream,
        Http3StreamDispatcher dispatcher,
        object dispatcherGate,
        ConnectionQPackState qpackState,
        CancellationToken cancellationToken)
    {
        await using (stream.ConfigureAwait(false))
        {
            long requestStartedTimestamp = 0;
            bool requestStarted = false;
            try
            {
                Http3RequestReadResult requestResult = await ReadRequestAsync(stream, qpackState, cancellationToken).ConfigureAwait(false);
                await using Http3StreamingRequestBodyReader? streamingBodyReader = requestResult.StreamingBodyReader;
                requestStartedTimestamp = Http3Metrics.GetTimestamp();
                requestStarted = true;
                Http3Metrics.RecordRequestStarted("server");
                EmitRequestStartedDiagnostic(diagnosticsSink, "server", stream.Id, requestResult.Method, requestResult.Path);
                if (TryGetWebSocketHandler(requestResult.Protocol, out IHttp3WebSocketHandler? tunnelHandler))
                {
                    Http3Request request = requestResult.ToRequest();
                    Http3ServerResponse acceptedResponse = new(
                        200,
                        ReadOnlyMemory<byte>.Empty,
                        webSocketAcceptResponseHeadersSelector?.Invoke(request));
                    if (!await WriteTunnelResponseHeadersAsync(stream, acceptedResponse, cancellationToken).ConfigureAwait(false))
                    {
                        return;
                    }
                    Http3WebSocketTunnelContext tunnelContext = new(request, stream);
                    CancellationTokenSource? keepAliveCancellation = null;
                    Task? keepAliveTask = null;
                    try
                    {
                        if (webSocketKeepAliveInterval is { } keepAliveInterval)
                        {
                            keepAliveCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                            keepAliveTask = RunWebSocketKeepAliveAsync(
                                tunnelContext,
                                keepAliveInterval,
                                webSocketKeepAlivePayload,
                                keepAliveCancellation.Token);
                        }

                        await tunnelHandler!.HandleAsync(tunnelContext, cancellationToken).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                    {
                        throw;
                    }
                    catch (QuicException)
                    {
                        throw;
                    }
                    catch (Exception exception)
                    {
                        await StopWebSocketKeepAliveAsync(keepAliveCancellation, keepAliveTask).ConfigureAwait(false);
                        keepAliveCancellation = null;
                        keepAliveTask = null;
                        Http3Metrics.RecordRequestFailed("server", "websocket", requestStartedTimestamp);
                        EmitError(exception);
                        Http3WebSocketClosePolicy closePolicy = ResolveWebSocketHandlerExceptionClosePolicy(exception);
                        await TryCloseWebSocketTunnelAsync(
                            tunnelContext,
                            closePolicy.StatusCode,
                            closePolicy.Reason,
                            cancellationToken).ConfigureAwait(false);
                        return;
                    }
                    finally
                    {
                        await StopWebSocketKeepAliveAsync(keepAliveCancellation, keepAliveTask).ConfigureAwait(false);
                    }

                    Http3Metrics.RecordRequestCompleted("server", acceptedResponse.StatusCode, requestStartedTimestamp);
                    EmitResponseCompletedDiagnostic(diagnosticsSink, "server", stream.Id, acceptedResponse.StatusCode, 0);
                    EmitRequestCompletedDiagnostic(diagnosticsSink, "server", stream.Id, request.Method, request.Path, acceptedResponse.StatusCode, 0);
                    return;
                }

                Http3ServerResponse response;
                if (requestResult.Protocol is not null && !Http3ExtendedConnect.IsSupportedProtocol(requestResult.Protocol))
                {
                    response = Http3ExtendedConnect.CreateUnsupportedProtocolResponse(requestResult.Protocol);
                }
                else if (requestResult.IsHeadersOnlyGet && handler is IHttp3HeadersOnlyRequestHandler headersOnlyHandler)
                {
                    response = await headersOnlyHandler.HandleHeadersOnlyAsync(requestResult.HeadersOnlyRequest, cancellationToken).ConfigureAwait(false);
                }
                else if (requestResult.IsStreaming && handler is IHttp3StreamingRequestHandler streamingHandler)
                {
                    response = await streamingHandler.HandleStreamingAsync(requestResult.StreamingRequest, cancellationToken).ConfigureAwait(false);
                }
                else
                {
                    response = await handler.HandleAsync(requestResult.ToRequest(), cancellationToken).ConfigureAwait(false);
                }

                if (!await WriteResponseAsync(stream, response, cancellationToken).ConfigureAwait(false))
                {
                    TryAbortResponseWrite(stream, Http3ErrorCode.RequestIncomplete);
                    return;
                }

                if (streamingBodyReader is not null)
                {
                    await streamingBodyReader.DrainAsync(cancellationToken).ConfigureAwait(false);
                }
                else if (requestResult.RequiresRequestDrain)
                {
                    await DrainHeadersOnlyRequestAsync(
                        stream,
                        requestResult.HeadersOnlyRequest.Headers,
                        qpackState,
                        cancellationToken).ConfigureAwait(false);
                }

                if (response.SendGoAwayAfterResponse)
                {
                    if (!await WriteGoAwayAsync(controlStream, checked((ulong)stream.Id), cancellationToken).ConfigureAwait(false))
                    {
                        return;
                    }
                }

                if (response.CloseConnectionAfterResponse)
                {
                    await connection.CloseAsync(0, cancellationToken).ConfigureAwait(false);
                }

                Http3Metrics.RecordRequestCompleted("server", response.StatusCode, requestStartedTimestamp);
                EmitResponseCompletedDiagnostic(diagnosticsSink, "server", stream.Id, response.StatusCode, response.Body.Length);
                EmitRequestCompletedDiagnostic(diagnosticsSink, "server", stream.Id, requestResult.Method, requestResult.Path, response.StatusCode, response.Body.Length);
            }
            catch (OperationCanceledException exception) when (cancellationToken.IsCancellationRequested)
            {
                if (requestStarted)
                {
                    Http3Metrics.RecordRequestFailed("server", "canceled", requestStartedTimestamp);
                }

                SuppressExpectedException(exception);
            }
            catch (QuicException exception)
            {
                if (requestStarted)
                {
                    Http3Metrics.RecordRequestFailed("server", "quic", requestStartedTimestamp);
                }

                SuppressExpectedException(exception);
            }
            catch (QPackException exception)
            {
                if (requestStarted)
                {
                    Http3Metrics.RecordRequestFailed("server", "qpack", requestStartedTimestamp);
                }

                EmitError(exception);
                await TryCloseConnectionAsync(connection, checked((long)exception.ErrorCode), cancellationToken).ConfigureAwait(false);
            }
            catch (Http3Exception exception)
            {
                if (requestStarted)
                {
                    Http3Metrics.RecordRequestFailed("server", "http3", requestStartedTimestamp);
                }

                EmitError(exception);
                await TryCloseConnectionAsync(connection, checked((long)exception.ErrorCode), cancellationToken).ConfigureAwait(false);
            }
            catch (ArgumentException exception)
            {
                if (requestStarted)
                {
                    Http3Metrics.RecordRequestFailed("server", "argument", requestStartedTimestamp);
                }

                EmitError(exception);
                await TryWriteResponseAsync(stream, CreateBadRequestResponse(), cancellationToken).ConfigureAwait(false);
            }
            catch (Exception exception)
            {
                if (requestStarted)
                {
                    Http3Metrics.RecordRequestFailed("server", "handler", requestStartedTimestamp);
                }

                EmitError(exception);
                throw;
            }
            finally
            {
                lock (dispatcherGate)
                {
                    dispatcher.TryCompleteRequestStream(checked((ulong)stream.Id));
                }

                EmitStreamClosedDiagnostic(diagnosticsSink, "server", stream.Id, Http3StreamKind.Request);
            }
        }
    }

    private bool TryGetWebSocketHandler(string? protocol, out IHttp3WebSocketHandler? tunnelHandler)
    {
        tunnelHandler = null;
        if (!Http3ExtendedConnect.IsSupportedProtocol(protocol) || webSocketHandler is null)
        {
            return false;
        }

        tunnelHandler = webSocketHandler;
        return true;
    }

    private static void TryAbortResponseWrite(QuicStream stream, Http3ErrorCode errorCode)
    {
        try
        {
            stream.Abort(QuicAbortDirection.Write, (long)errorCode);
        }
        catch (Exception exception) when (exception is QuicException or ObjectDisposedException or InvalidOperationException)
        {
            SuppressExpectedException(exception);
        }
    }

    private async ValueTask<Http3RequestReadResult> ReadRequestAsync(
        QuicStream stream,
        ConnectionQPackState qpackState,
        CancellationToken cancellationToken)
    {
        if (handler is IHttp3StreamingRequestHandler streamingHandler)
        {
            Http3StreamingRequestBodyReader streamingReader = await Http3StreamingRequestBodyReader.CreateAsync(
                this,
                stream,
                qpackState,
                readBufferSize,
                cancellationToken).ConfigureAwait(false);
            try
            {
                if (streamingHandler.CanHandleStreaming(streamingReader.Request))
                {
                    streamingReader.SetRetainBodyChunks(
                        streamingHandler.RetainStreamingRequestBodyChunks(streamingReader.Request));
                    return Http3RequestReadResult.FromStreaming(streamingReader.Request, streamingReader);
                }

                Http3Request bufferedRequest = await streamingReader.ReadBufferedRequestAsync(cancellationToken).ConfigureAwait(false);
                await streamingReader.DisposeAsync().ConfigureAwait(false);
                return Http3RequestReadResult.FromRequest(bufferedRequest);
            }
            catch
            {
                await streamingReader.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }

        Http3FrameReader? frameReader = null;
        Http3RequestMessageValidator? validator = null;
        ArrayBufferWriter<byte>? body = null;
        // CONTEXT: Request read buffering
        // SEE: spec:REQ-QUIC-RFC9114-S4-0002
        // SEE: code:src/Incursa.Quic.Http3/Http3FrameReader.cs#Read
        // SEE: code:src/Incursa.Quic.Http3/Http3RequestMessageValidator.cs#ReceiveData
        // A pooled buffer is used here because frame parsing spans multiple
        // awaited reads and the frame reader may hold partial bytes until it
        // can complete a frame.
        byte[] buffer = QuicBufferPool.RentBytes(readBufferSize);

        try
        {
            while (true)
            {
                int bytesRead = await stream.TryReadTerminalAsync(buffer.AsMemory(0, readBufferSize), cancellationToken).ConfigureAwait(false);
                if (bytesRead == 0)
                {
                    if (frameReader is not null)
                    {
                        foreach (Http3Frame frame in frameReader.Complete())
                        {
                            EmitFrame(Http3DiagnosticKind.FrameReceived, stream.Id, frame);
                            validator ??= new Http3RequestMessageValidator();
                            body = await ProcessRequestFrameAsync(frame, validator, body, stream.Id, qpackState, cancellationToken).ConfigureAwait(false);
                        }
                    }

                    break;
                }

                if (frameReader is null
                    && !IsDiagnosticEnabled(diagnosticsSink, Http3DiagnosticKind.FrameReceived)
                    && await TryReadHeadersOnlyRequestFastPathAsync(
                        buffer.AsMemory(0, bytesRead),
                        stream.Id,
                        qpackState,
                        cancellationToken).ConfigureAwait(false) is { } fastPathRequest)
                {
                    return Http3RequestReadResult.FromHeadersOnly(fastPathRequest, requiresRequestDrain: true);
                }

                frameReader ??= new Http3FrameReader(ValidateRequestStreamFrameType);
                validator ??= new Http3RequestMessageValidator();
                foreach (Http3Frame frame in frameReader.Read(buffer.AsSpan(0, bytesRead)))
                {
                    EmitFrame(Http3DiagnosticKind.FrameReceived, stream.Id, frame);
                    body = await ProcessRequestFrameAsync(frame, validator, body, stream.Id, qpackState, cancellationToken).ConfigureAwait(false);
                }

                if (TryCreateHeadersOnlyRequest(validator.Headers, out Http3HeadersOnlyRequest request))
                {
                    return Http3RequestReadResult.FromHeadersOnly(request);
                }
            }

            if (validator is null)
            {
                throw new Http3Exception(Http3ErrorCode.MessageError, "HTTP/3 request stream ended without request headers.");
            }

            validator.Complete();
            IReadOnlyList<QPackFieldLine>? headers = validator.Headers;
            if (headers is null)
            {
                throw new Http3Exception(Http3ErrorCode.MessageError, "The HTTP/3 request did not contain a HEADERS frame.");
            }

            return Http3RequestReadResult.FromRequest(CreateOwnedRequest(headers, body?.WrittenMemory ?? ReadOnlyMemory<byte>.Empty));
        }
        finally
        {
            QuicBufferPool.ReturnBytes(buffer);
        }
    }

    private async ValueTask DrainHeadersOnlyRequestAsync(
        QuicStream stream,
        IReadOnlyList<QPackFieldLine> headers,
        ConnectionQPackState qpackState,
        CancellationToken cancellationToken)
    {
        Http3FrameReader frameReader = new(ValidateRequestStreamFrameType);
        Http3RequestMessageValidator validator = new();
        validator.ReceiveOwnedHeaders(headers);
        byte[] buffer = QuicBufferPool.RentBytes(readBufferSize);

        try
        {
            while (true)
            {
                int bytesRead = await stream.TryReadTerminalAsync(buffer.AsMemory(0, readBufferSize), cancellationToken).ConfigureAwait(false);
                IEnumerable<Http3Frame> frames = bytesRead == 0
                    ? frameReader.Complete()
                    : frameReader.Read(buffer.AsSpan(0, bytesRead));

                foreach (Http3Frame frame in frames)
                {
                    EmitFrame(Http3DiagnosticKind.FrameReceived, stream.Id, frame);
                    await ProcessDrainedRequestFrameAsync(frame, validator, stream.Id, qpackState, cancellationToken).ConfigureAwait(false);
                }

                if (bytesRead == 0)
                {
                    validator.Complete();
                    return;
                }
            }
        }
        finally
        {
            QuicBufferPool.ReturnBytes(buffer);
        }
    }

    private static async ValueTask<Http3HeadersOnlyRequest?> TryReadHeadersOnlyRequestFastPathAsync(
        ReadOnlyMemory<byte> bytes,
        long streamId,
        ConnectionQPackState qpackState,
        CancellationToken cancellationToken)
    {
        if (!TryReadSingleCompleteHeadersPayload(bytes, out ReadOnlyMemory<byte> encodedFieldSection))
        {
            return null;
        }

        if (encodedFieldSection.IsEmpty || encodedFieldSection.Span[0] != 0)
        {
            return null;
        }

        IReadOnlyList<QPackFieldLine> fieldSection = await qpackState.DecodeRequestHeadersAsync(
                checked((ulong)streamId),
                encodedFieldSection,
                cancellationToken).ConfigureAwait(false);
        return TryCreateHeadersOnlyRequest(fieldSection, out Http3HeadersOnlyRequest request) ? request : null;
    }

    private static bool TryReadSingleCompleteHeadersPayload(
        ReadOnlyMemory<byte> bytes,
        out ReadOnlyMemory<byte> payload)
    {
        payload = default;
        ReadOnlySpan<byte> span = bytes.Span;
        int index = 0;
        if (!TryReadVariableLengthInteger(span, ref index, out ulong frameType)
            || !TryReadVariableLengthInteger(span, ref index, out ulong payloadLength))
        {
            return false;
        }

        if (payloadLength > int.MaxValue)
        {
            throw new Http3Exception(Http3ErrorCode.ExcessiveLoad, "The HTTP/3 frame payload is too large for this parser.");
        }

        if (frameType != (ulong)Http3FrameType.Headers || span.Length - index != (int)payloadLength)
        {
            return false;
        }

        payload = bytes.Slice(index, (int)payloadLength);
        return true;
    }

    private static bool TryReadVariableLengthInteger(ReadOnlySpan<byte> source, ref int index, out ulong value)
    {
        value = default;
        if (index >= source.Length)
        {
            return false;
        }

        if (Http3VariableLengthInteger.TryParse(source[index..], out value, out int bytesConsumed))
        {
            index += bytesConsumed;
            return true;
        }

        return false;
    }

    private static bool TryCreateHeadersOnlyRequest(
        IReadOnlyList<QPackFieldLine>? headers,
        out Http3HeadersOnlyRequest request)
    {
        request = default;
        if (headers is null)
        {
            return false;
        }

        if (HasContentLength(headers))
        {
            return false;
        }

        Http3HeaderValidationResult result = Http3HeaderValidator.ValidateRequestHeaders(headers, validateContentLength: false);
        if (result.Method != "GET" && !Http3ExtendedConnect.IsExtendedConnect(result))
        {
            return false;
        }

        request = new Http3HeadersOnlyRequest(result.Method!, result.Scheme ?? string.Empty, result.Authority ?? string.Empty, result.Path ?? string.Empty, result.Protocol, headers);
        return true;
    }

    private static bool HasContentLength(IReadOnlyList<QPackFieldLine> headers)
    {
        for (int index = 0; index < headers.Count; index++)
        {
            QPackFieldLine header = headers[index];
            if (StringComparer.Ordinal.Equals(header.Name, "content-length"))
            {
                return true;
            }
        }

        return false;
    }

    private async ValueTask<ArrayBufferWriter<byte>?> ProcessRequestFrameAsync(
        Http3Frame frame,
        Http3RequestMessageValidator validator,
        ArrayBufferWriter<byte>? body,
        long streamId,
        ConnectionQPackState qpackState,
        CancellationToken cancellationToken)
    {
        switch (frame)
        {
            case Http3HeadersFrame headersFrame:
                IReadOnlyList<QPackFieldLine> fieldSection = await qpackState.DecodeRequestHeadersAsync(
                        checked((ulong)streamId),
                        headersFrame.EncodedFieldSection,
                        cancellationToken).ConfigureAwait(false);
                validator.ReceiveOwnedHeaders(fieldSection);
                return body;
            case Http3DataFrame dataFrame:
                validator.ReceiveData(checked((ulong)dataFrame.Data.Length));
                body ??= new ArrayBufferWriter<byte>();
                body.Write(dataFrame.Data.Span);
                return body;
            case Http3UnknownFrame:
                return body;
            default:
                throw new Http3Exception(Http3ErrorCode.FrameUnexpected, "The request stream contained an invalid frame type.");
        }
    }

    private async ValueTask ProcessDrainedRequestFrameAsync(
        Http3Frame frame,
        Http3RequestMessageValidator validator,
        long streamId,
        ConnectionQPackState qpackState,
        CancellationToken cancellationToken)
    {
        switch (frame)
        {
            case Http3HeadersFrame headersFrame:
                IReadOnlyList<QPackFieldLine> fieldSection = await qpackState.DecodeRequestHeadersAsync(
                        checked((ulong)streamId),
                        headersFrame.EncodedFieldSection,
                        cancellationToken).ConfigureAwait(false);
                validator.ReceiveOwnedHeaders(fieldSection);
                break;
            case Http3DataFrame dataFrame:
                validator.ReceiveData(checked((ulong)dataFrame.Data.Length));
                break;
            case Http3UnknownFrame:
                break;
            default:
                throw new Http3Exception(Http3ErrorCode.FrameUnexpected, "The request stream contained an invalid frame type.");
        }
    }

    private static Http3Exception? ValidateRequestStreamFrameType(ulong frameType)
    {
        return frameType switch
        {
            (ulong)Http3FrameType.Data or (ulong)Http3FrameType.Headers => null,
            (ulong)Http3FrameType.CancelPush
                or (ulong)Http3FrameType.Settings
                or (ulong)Http3FrameType.PushPromise
                or (ulong)Http3FrameType.GoAway
                or (ulong)Http3FrameType.MaxPushId => new Http3Exception(
                    Http3ErrorCode.FrameUnexpected,
                    "The request stream contained an invalid frame type."),
            _ => null,
        };
    }

    private void ProcessPeerControlBytes(
        Http3FrameReader frameReader,
        ReadOnlySpan<byte> bytes,
        long streamId,
        Http3StreamDispatcher dispatcher,
        object dispatcherGate,
        ConnectionQPackState qpackState)
    {
        if (bytes.IsEmpty)
        {
            return;
        }

        ProcessPeerControlFrames(frameReader.Read(bytes), streamId, dispatcher, dispatcherGate, qpackState);
    }

    private void ProcessPeerControlFrames(
        IEnumerable<Http3Frame> frames,
        long streamId,
        Http3StreamDispatcher dispatcher,
        object dispatcherGate,
        ConnectionQPackState qpackState)
    {
        foreach (Http3Frame frame in frames)
        {
            lock (dispatcherGate)
            {
                dispatcher.ReceiveFrame(checked((ulong)streamId), frame);
            }

            EmitFrame(Http3DiagnosticKind.FrameReceived, streamId, frame);
            if (frame is Http3SettingsFrame settingsFrame)
            {
                Http3StreamInfo streamInfo = dispatcher.GetStreamInfo(checked((ulong)streamId));
                if (streamInfo.Initiator == Http3StreamInitiator.Client)
                {
                    qpackState.SetPeerSettings(settingsFrame.Values);
                }

                if (IsDiagnosticEnabled(diagnosticsSink, Http3DiagnosticKind.SettingsReceived))
                {
                    diagnosticsSink!.Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.SettingsReceived)
                    {
                        Role = "server",
                        StreamId = streamId,
                    });
                }
            }
        }
    }

    private static Http3Request CreateOwnedRequest(IReadOnlyList<QPackFieldLine> headers, ReadOnlyMemory<byte> body)
    {
        Http3HeaderValidationResult result = Http3HeaderValidator.ValidateRequestHeaders(headers, checked((ulong)body.Length));
        return new Http3Request(
            result.Method!,
            result.Scheme ?? string.Empty,
            result.Authority ?? string.Empty,
            result.Path ?? string.Empty,
            result.Protocol,
            headers,
            body,
            copyBody: false);
    }

    private sealed class Http3StreamingRequestBodyReader : IAsyncEnumerable<ReadOnlyMemory<byte>>, IAsyncDisposable
    {
        private const int InitialReadBufferSize = 4 * 1024;
        private readonly Http3Server owner;
        private readonly QuicStream stream;
        private readonly ConnectionQPackState qpackState;
        private readonly int readBufferSize;
        private readonly Http3StreamingFrameReader frameReader = new(ValidateRequestStreamFrameType);
        private readonly Http3RequestMessageValidator validator = new();
        private readonly Queue<Http3StreamingFramePart> pendingParts = [];
        private readonly SemaphoreSlim readGate = new(1, 1);
        private byte[] buffer;
        private int enumerated;
        private int disposed;
        private bool bodyDataObserved;
        private bool completed;
        private bool retainBodyChunks = true;

        private Http3StreamingRequestBodyReader(
            Http3Server owner,
            QuicStream stream,
            ConnectionQPackState qpackState,
            int readBufferSize)
        {
            this.owner = owner;
            this.stream = stream;
            this.qpackState = qpackState;
            this.readBufferSize = readBufferSize;
            buffer = QuicBufferPool.RentBytes(Math.Min(readBufferSize, InitialReadBufferSize));
        }

        public Http3StreamingRequest Request { get; private set; } = null!;

        public static async ValueTask<Http3StreamingRequestBodyReader> CreateAsync(
            Http3Server owner,
            QuicStream stream,
            ConnectionQPackState qpackState,
            int readBufferSize,
            CancellationToken cancellationToken)
        {
            Http3StreamingRequestBodyReader reader = new(owner, stream, qpackState, readBufferSize);
            try
            {
                await reader.ReadInitialHeadersAsync(cancellationToken).ConfigureAwait(false);
                return reader;
            }
            catch
            {
                await reader.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }

        public IAsyncEnumerator<ReadOnlyMemory<byte>> GetAsyncEnumerator(CancellationToken cancellationToken = default)
        {
            if (Interlocked.Exchange(ref enumerated, 1) != 0)
            {
                throw new InvalidOperationException("The HTTP/3 streaming request body can be enumerated only once.");
            }

            return EnumerateAsync(cancellationToken).GetAsyncEnumerator(cancellationToken);
        }

        public void SetRetainBodyChunks(bool retain)
        {
            if (Volatile.Read(ref enumerated) != 0)
            {
                throw new InvalidOperationException("The HTTP/3 request body retention mode cannot change after enumeration starts.");
            }

            retainBodyChunks = retain;
        }

        public async ValueTask<Http3Request> ReadBufferedRequestAsync(CancellationToken cancellationToken)
        {
            ReadOnlyMemory<byte> firstSegment = default;
            List<ReadOnlyMemory<byte>>? bodySegments = null;
            int bodyLength = 0;
            while (await ReadNextDataAsync(cancellationToken).ConfigureAwait(false) is { HasData: true } next)
            {
                if (next.Data.IsEmpty)
                {
                    continue;
                }

                if (bodySegments is not null)
                {
                    bodySegments.Add(next.Data);
                    bodyLength = checked(bodyLength + next.Data.Length);
                    continue;
                }

                if (firstSegment.IsEmpty)
                {
                    firstSegment = next.Data;
                    continue;
                }

                bodySegments = [firstSegment, next.Data];
                bodyLength = checked(firstSegment.Length + next.Data.Length);
                firstSegment = default;
            }

            if (bodySegments is null)
            {
                return CreateOwnedRequest(
                    Request.Headers,
                    firstSegment.IsEmpty ? ReadOnlyMemory<byte>.Empty : firstSegment.ToArray());
            }

            byte[] body = GC.AllocateUninitializedArray<byte>(bodyLength);
            int offset = 0;
            foreach (ReadOnlyMemory<byte> segment in bodySegments)
            {
                segment.Span.CopyTo(body.AsSpan(offset));
                offset += segment.Length;
            }

            return CreateOwnedRequest(Request.Headers, body);
        }

        public async ValueTask DrainAsync(CancellationToken cancellationToken)
        {
            while (true)
            {
                StreamingBodyReadResult next = await ReadNextDataAsync(cancellationToken).ConfigureAwait(false);
                if (!next.HasData)
                {
                    return;
                }
            }
        }

        public ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref disposed, 1) == 0)
            {
                frameReader.Dispose();
                QuicBufferPool.ReturnBytes(buffer);
                readGate.Dispose();
            }

            return ValueTask.CompletedTask;
        }

        private async IAsyncEnumerable<ReadOnlyMemory<byte>> EnumerateAsync(
            [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            while (await ReadNextDataAsync(cancellationToken).ConfigureAwait(false) is { HasData: true } next)
            {
                try
                {
                    yield return next.Data;
                }
                finally
                {
                    if (!retainBodyChunks)
                    {
                        frameReader.ReleaseData(next.Data);
                    }
                }
            }
        }

        private async ValueTask ReadInitialHeadersAsync(CancellationToken cancellationToken)
        {
            while (Request is null)
            {
                int bytesRead = await stream.TryReadTerminalAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (bytesRead == 0)
                {
                    frameReader.Complete();
                }
                else
                {
                    frameReader.Read(buffer.AsMemory(0, bytesRead), pendingParts);
                }

                while (Request is null && pendingParts.TryDequeue(out Http3StreamingFramePart part))
                {
                    EmitFrame(part);
                    await ProcessInitialPartAsync(part, cancellationToken).ConfigureAwait(false);
                }

                if (bytesRead == 0 && Request is null)
                {
                    throw new Http3Exception(Http3ErrorCode.MessageError, "HTTP/3 request stream ended without request headers.");
                }
            }
        }

        private async ValueTask ProcessInitialPartAsync(Http3StreamingFramePart part, CancellationToken cancellationToken)
        {
            if (part.IsData)
            {
                validator.ReceiveData(checked((ulong)part.Data.Length));
                return;
            }

            Http3Frame frame = part.Frame!;
            switch (frame)
            {
                case Http3HeadersFrame headersFrame:
                    IReadOnlyList<QPackFieldLine> headers = await qpackState.DecodeRequestHeadersAsync(
                            checked((ulong)stream.Id),
                            headersFrame.EncodedFieldSection,
                            cancellationToken).ConfigureAwait(false);
                    validator.ReceiveOwnedHeaders(headers);
                    Http3HeaderValidationResult result = Http3HeaderValidator.ValidateRequestHeaders(headers, validateContentLength: false);
                    Request = new Http3StreamingRequest(
                        result.Method!,
                        result.Scheme ?? string.Empty,
                        result.Authority ?? string.Empty,
                        result.Path ?? string.Empty,
                        result.Protocol,
                        headers,
                        this);
                    break;
                case Http3UnknownFrame:
                    break;
                default:
                    throw new Http3Exception(Http3ErrorCode.FrameUnexpected, "The request stream contained an invalid frame type.");
            }
        }

        private async ValueTask<StreamingBodyReadResult> ReadNextDataAsync(CancellationToken cancellationToken)
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
            await readGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                while (!completed)
                {
                    if (pendingParts.TryDequeue(out Http3StreamingFramePart pending))
                    {
                        EmitFrame(pending);
                        StreamingBodyReadResult result = await ProcessBodyPartAsync(pending, cancellationToken).ConfigureAwait(false);
                        if (result.HasData)
                        {
                            return result;
                        }

                        continue;
                    }

                    EnsureBodyReadBuffer();
                    int bytesRead = await stream.TryReadTerminalAsync(buffer, cancellationToken).ConfigureAwait(false);
                    if (bytesRead == 0)
                    {
                        frameReader.Complete();
                    }
                    else
                    {
                        frameReader.Read(buffer.AsMemory(0, bytesRead), pendingParts);
                    }

                    if (bytesRead == 0 && pendingParts.Count == 0)
                    {
                        validator.Complete();
                        completed = true;
                    }
                }

                return default;
            }
            finally
            {
                readGate.Release();
            }
        }

        private async ValueTask<StreamingBodyReadResult> ProcessBodyPartAsync(
            Http3StreamingFramePart part,
            CancellationToken cancellationToken)
        {
            if (part.IsData)
            {
                bodyDataObserved = true;
                validator.ReceiveData(checked((ulong)part.Data.Length));
                return new StreamingBodyReadResult(true, part.Data);
            }

            Http3Frame frame = part.Frame!;
            switch (frame)
            {
                case Http3HeadersFrame headersFrame:
                    IReadOnlyList<QPackFieldLine> headers = await qpackState.DecodeRequestHeadersAsync(
                            checked((ulong)stream.Id),
                            headersFrame.EncodedFieldSection,
                            cancellationToken).ConfigureAwait(false);
                    validator.ReceiveOwnedHeaders(headers);
                    return default;
                case Http3UnknownFrame:
                    return default;
                default:
                    throw new Http3Exception(Http3ErrorCode.FrameUnexpected, "The request stream contained an invalid frame type.");
            }
        }

        private void EnsureBodyReadBuffer()
        {
            if (!bodyDataObserved || buffer.Length >= readBufferSize)
            {
                return;
            }

            byte[] priorBuffer = buffer;
            buffer = QuicBufferPool.RentBytes(readBufferSize);
            QuicBufferPool.ReturnBytes(priorBuffer);
        }

        private void EmitFrame(Http3StreamingFramePart part)
        {
            if (part.IsData)
            {
                if (part.EndsFrame)
                {
                    owner.EmitFrame(Http3DiagnosticKind.FrameReceived, stream.Id, Http3FrameType.Data, part.FramePayloadLength);
                }

                return;
            }

            owner.EmitFrame(Http3DiagnosticKind.FrameReceived, stream.Id, part.Frame!);
        }

        private readonly record struct StreamingBodyReadResult(bool HasData, ReadOnlyMemory<byte> Data);
    }

    private readonly struct Http3RequestReadResult
    {
        private readonly Http3Request? request;
        private readonly Http3StreamingRequest? streamingRequest;

        private Http3RequestReadResult(
            Http3HeadersOnlyRequest headersOnlyRequest,
            Http3Request? request,
            Http3StreamingRequest? streamingRequest,
            Http3StreamingRequestBodyReader? streamingBodyReader,
            bool isHeadersOnly,
            bool requiresRequestDrain)
        {
            HeadersOnlyRequest = headersOnlyRequest;
            this.request = request;
            this.streamingRequest = streamingRequest;
            StreamingBodyReader = streamingBodyReader;
            IsHeadersOnly = isHeadersOnly;
            RequiresRequestDrain = requiresRequestDrain;
        }

        public Http3HeadersOnlyRequest HeadersOnlyRequest { get; }

        public bool IsHeadersOnly { get; }

        public bool RequiresRequestDrain { get; }

        public bool IsStreaming => streamingRequest is not null;

        public Http3StreamingRequest StreamingRequest => streamingRequest
            ?? throw new InvalidOperationException("The request does not use the streaming handler path.");

        public Http3StreamingRequestBodyReader? StreamingBodyReader { get; }

        public bool IsHeadersOnlyGet => IsHeadersOnly
            && HeadersOnlyRequest.Protocol is null
            && string.Equals(HeadersOnlyRequest.Method, "GET", StringComparison.Ordinal);

        public string Method => IsHeadersOnly
            ? HeadersOnlyRequest.Method
            : streamingRequest?.Method ?? request!.Method;

        public string Path => IsHeadersOnly
            ? HeadersOnlyRequest.Path
            : streamingRequest?.Path ?? request!.Path;

        public string? Protocol
        {
            get
            {
                if (IsHeadersOnly)
                {
                    return HeadersOnlyRequest.Protocol;
                }

                return streamingRequest is not null ? streamingRequest.Protocol : request!.Protocol;
            }
        }

        public static Http3RequestReadResult FromHeadersOnly(
            Http3HeadersOnlyRequest request,
            bool requiresRequestDrain = false)
            => new(request, null, null, null, isHeadersOnly: true, requiresRequestDrain);

        public static Http3RequestReadResult FromRequest(Http3Request request)
            => new(default, request ?? throw new ArgumentNullException(nameof(request)), null, null, isHeadersOnly: false, requiresRequestDrain: false);

        public static Http3RequestReadResult FromStreaming(
            Http3StreamingRequest request,
            Http3StreamingRequestBodyReader bodyReader)
            => new(
                default,
                null,
                request ?? throw new ArgumentNullException(nameof(request)),
                bodyReader ?? throw new ArgumentNullException(nameof(bodyReader)),
                isHeadersOnly: false,
                requiresRequestDrain: false);

        public Http3Request ToRequest()
        {
            if (request is not null)
            {
                return request;
            }

            if (streamingRequest is not null)
            {
                throw new InvalidOperationException("A streaming request cannot be converted to a buffered request.");
            }

            return new Http3Request(
                HeadersOnlyRequest.Method,
                HeadersOnlyRequest.Scheme,
                HeadersOnlyRequest.Authority,
                HeadersOnlyRequest.Path,
                HeadersOnlyRequest.Protocol,
                HeadersOnlyRequest.Headers,
                ReadOnlyMemory<byte>.Empty);
        }
    }

    private static async ValueTask TryCloseConnectionAsync(
        QuicConnection connection,
        long errorCode,
        CancellationToken cancellationToken)
    {
        try
        {
            await connection.CloseAsync(errorCode, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException exception) when (cancellationToken.IsCancellationRequested)
        {
            SuppressExpectedException(exception);
        }
        catch (QuicException exception)
        {
            SuppressExpectedException(exception);
        }
        catch (ObjectDisposedException exception)
        {
            SuppressExpectedException(exception);
        }
        catch (InvalidOperationException exception)
        {
            SuppressExpectedException(exception);
        }
    }

    private async ValueTask TryWriteResponseAsync(
        QuicStream stream,
        Http3ServerResponse response,
        CancellationToken cancellationToken)
    {
        try
        {
            _ = await WriteResponseAsync(stream, response, cancellationToken).ConfigureAwait(false);
        }
        catch (QuicException exception)
        {
            SuppressExpectedException(exception);
        }
        catch (ObjectDisposedException exception)
        {
            SuppressExpectedException(exception);
        }
    }

    private static async ValueTask TryCloseWebSocketTunnelAsync(
        Http3WebSocketTunnelContext tunnelContext,
        ushort statusCode,
        string? reason,
        CancellationToken cancellationToken)
    {
        try
        {
            await tunnelContext.CloseAsync(statusCode, reason, cancellationToken).ConfigureAwait(false);
        }
        catch (QuicException exception)
        {
            SuppressExpectedException(exception);
        }
        catch (ObjectDisposedException exception)
        {
            SuppressExpectedException(exception);
        }
    }

    private Http3WebSocketClosePolicy ResolveWebSocketHandlerExceptionClosePolicy(Exception handlerException)
    {
        if (webSocketHandlerExceptionClosePolicySelector is null)
        {
            return new Http3WebSocketClosePolicy(webSocketHandlerExceptionCloseStatusCode, webSocketHandlerExceptionCloseReason);
        }

        try
        {
            Http3WebSocketClosePolicy? selected = webSocketHandlerExceptionClosePolicySelector(handlerException);
            if (selected is { } policy)
            {
                _ = Http3WebSocketCloseFrameParser.FormatPayload(policy.StatusCode, policy.Reason);
                return policy;
            }
        }
        catch (Exception exception)
        {
            EmitError(exception);
        }

        return new Http3WebSocketClosePolicy(webSocketHandlerExceptionCloseStatusCode, webSocketHandlerExceptionCloseReason);
    }

    private async Task RunWebSocketKeepAliveAsync(
        Http3WebSocketTunnelContext tunnelContext,
        TimeSpan interval,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken)
    {
        try
        {
            while (true)
            {
                await Task.Delay(interval, cancellationToken).ConfigureAwait(false);
                await tunnelContext.PingAsync(payload, cancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException exception) when (cancellationToken.IsCancellationRequested)
        {
            SuppressExpectedException(exception);
        }
        catch (QuicException exception)
        {
            SuppressExpectedException(exception);
        }
        catch (ObjectDisposedException exception)
        {
            SuppressExpectedException(exception);
        }
        catch (Exception exception)
        {
            EmitError(exception);
        }
    }

    private static async ValueTask StopWebSocketKeepAliveAsync(
        CancellationTokenSource? cancellation,
        Task? keepAliveTask)
    {
        if (cancellation is null || keepAliveTask is null)
        {
            return;
        }

        try
        {
            await cancellation.CancelAsync().ConfigureAwait(false);
            await keepAliveTask.ConfigureAwait(false);
        }
        finally
        {
            cancellation.Dispose();
        }
    }

    private ValueTask<bool> WriteResponseAsync(
        QuicStream stream,
        Http3ServerResponse response,
        CancellationToken cancellationToken)
    {
        ResponseHeadersFrame headersFrame = GetResponseHeadersFrame(response);
        if (TryGetCompleteFixedResponseFrame(response, headersFrame.FrameBytes, out byte[]? completeResponseFrame))
        {
            return CompleteResponseWriteAsync(
                stream,
                response,
                headersFrame,
                WriteFinalFrameBytesAsync(stream, completeResponseFrame, cancellationToken),
                emitDataFrames: true);
        }

        if (response.StreamingBody is null && response.Body.IsEmpty)
        {
            return CompleteResponseWriteAsync(
                stream,
                response,
                headersFrame,
                WriteFinalFrameBytesAsync(stream, headersFrame.FrameBytes, cancellationToken),
                emitDataFrames: false);
        }

        return WriteResponseSlowAsync(stream, response, headersFrame, cancellationToken);
    }

    private ValueTask<bool> CompleteResponseWriteAsync(
        QuicStream stream,
        Http3ServerResponse response,
        ResponseHeadersFrame headersFrame,
        ValueTask<bool> write,
        bool emitDataFrames)
    {
        if (write.IsCompletedSuccessfully)
        {
            return new ValueTask<bool>(CompleteResponseWrite(stream, response, headersFrame, write.Result, emitDataFrames));
        }

        return CompleteResponseWriteSlowAsync(stream, response, headersFrame, write, emitDataFrames);
    }

    private async ValueTask<bool> CompleteResponseWriteSlowAsync(
        QuicStream stream,
        Http3ServerResponse response,
        ResponseHeadersFrame headersFrame,
        ValueTask<bool> write,
        bool emitDataFrames)
    {
        return CompleteResponseWrite(
            stream,
            response,
            headersFrame,
            await write.ConfigureAwait(false),
            emitDataFrames);
    }

    private bool CompleteResponseWrite(
        QuicStream stream,
        Http3ServerResponse response,
        ResponseHeadersFrame headersFrame,
        bool written,
        bool emitDataFrames)
    {
        if (!written)
        {
            return false;
        }

        EmitFrame(Http3DiagnosticKind.FrameSent, stream.Id, Http3FrameType.Headers, headersFrame.FrameLength);
        EmitResponseStartedDiagnostic(diagnosticsSink, "server", stream.Id, response.StatusCode);
        if (emitDataFrames)
        {
            EmitResponseDataFrames(stream, response.Body, response.DataFramePayloadSize);
        }

        return true;
    }

    private async ValueTask<bool> WriteResponseSlowAsync(
        QuicStream stream,
        Http3ServerResponse response,
        ResponseHeadersFrame headersFrame,
        CancellationToken cancellationToken)
    {
        if (response.StreamingBody is not null)
        {
            if (!await WriteFrameBytesAsync(stream, headersFrame.FrameBytes, cancellationToken).ConfigureAwait(false))
            {
                return false;
            }
        }
        else
        {
            if (!await WriteFrameBytesAsync(stream, headersFrame.FrameBytes, cancellationToken).ConfigureAwait(false)
                || !await WriteFixedResponseDataFramesAsync(stream, response, cancellationToken).ConfigureAwait(false))
            {
                return false;
            }
        }

        EmitFrame(Http3DiagnosticKind.FrameSent, stream.Id, Http3FrameType.Headers, headersFrame.FrameLength);
        EmitResponseStartedDiagnostic(diagnosticsSink, "server", stream.Id, response.StatusCode);

        if (response.StreamingBody is not null)
        {
            if (!await WriteStreamingResponseDataFramesAsync(stream, response.StreamingBody, response.DataFramePayloadSize, cancellationToken).ConfigureAwait(false))
            {
                return false;
            }
        }
        else
        {
            EmitResponseDataFrames(stream, response.Body, response.DataFramePayloadSize);
        }

        return true;
    }

    private static bool TryGetCompleteFixedResponseFrame(
        Http3ServerResponse response,
        byte[] headersFrame,
        [NotNullWhen(true)] out byte[]? completeResponseFrame)
    {
        completeResponseFrame = null;
        if (response.StreamingBody is not null || response.Body.IsEmpty)
        {
            return false;
        }

        if (!response.CacheEncodedHeaders)
        {
            return false;
        }

        int framePayloadSize = response.DataFramePayloadSize ?? ResponseDataFrameChunkSize;
        byte[]? cachedFrame = response.GetCachedCompleteResponseFrame();
        if (cachedFrame is not null)
        {
            completeResponseFrame = cachedFrame;
            return true;
        }

        int completeResponseLength = headersFrame.Length;
        int bodyOffset = 0;
        while (bodyOffset < response.Body.Length)
        {
            int payloadLength = Math.Min(framePayloadSize, response.Body.Length - bodyOffset);
            completeResponseLength = checked(
                completeResponseLength
                + Http3FrameWriter.GetFrameLength((ulong)Http3FrameType.Data, payloadLength));
            if (completeResponseLength > MaximumCachedCompleteResponseBytes)
            {
                return false;
            }

            bodyOffset += payloadLength;
        }

        lock (response.CacheGate)
        {
            cachedFrame = response.GetCachedCompleteResponseFrame();
            if (cachedFrame is not null)
            {
                completeResponseFrame = cachedFrame;
                return true;
            }

            byte[] combinedFrame = GC.AllocateUninitializedArray<byte>(completeResponseLength);
            headersFrame.CopyTo(combinedFrame, 0);
            int destinationOffset = headersFrame.Length;
            bodyOffset = 0;
            while (bodyOffset < response.Body.Length)
            {
                int payloadLength = Math.Min(framePayloadSize, response.Body.Length - bodyOffset);
                byte[] dataFrameHeader = GetDataFrameHeader(payloadLength);
                dataFrameHeader.CopyTo(combinedFrame, destinationOffset);
                destinationOffset += dataFrameHeader.Length;
                response.Body.Span.Slice(bodyOffset, payloadLength).CopyTo(combinedFrame.AsSpan(destinationOffset));
                destinationOffset += payloadLength;
                bodyOffset += payloadLength;
            }

            if (destinationOffset != combinedFrame.Length)
            {
                throw new InvalidOperationException("The cached HTTP/3 response length did not match the serialized frame sequence.");
            }

            completeResponseFrame = response.CacheCompleteResponseFrame(combinedFrame);
            return true;
        }
    }

    private async ValueTask<bool> WriteTunnelResponseHeadersAsync(
        QuicStream stream,
        Http3ServerResponse response,
        CancellationToken cancellationToken)
    {
        ResponseHeadersFrame headersFrame = GetResponseHeadersFrame(response);
        if (!await WriteFrameBytesAsync(stream, headersFrame.FrameBytes, cancellationToken).ConfigureAwait(false))
        {
            return false;
        }

        EmitFrame(Http3DiagnosticKind.FrameSent, stream.Id, Http3FrameType.Headers, headersFrame.FrameLength);
        EmitResponseStartedDiagnostic(diagnosticsSink, "server", stream.Id, response.StatusCode);
        return true;
    }

    private ResponseHeadersFrame GetResponseHeadersFrame(Http3ServerResponse response)
    {
        if (response.CacheEncodedHeaders)
        {
            byte[]? cachedFrame = response.GetCachedHeadersFrame();
            if (cachedFrame is null)
            {
                ResponseHeadersFrame frame = CreateResponseHeadersFrame(response);
                cachedFrame = response.CacheHeadersFrame(frame.FrameBytes);
            }

            return new ResponseHeadersFrame(cachedFrame, cachedFrame.Length);
        }

        return CreateResponseHeadersFrame(response);
    }

    private static ResponseHeadersFrame CreateResponseHeadersFrame(Http3ServerResponse response)
    {
        byte[] encodedFieldSection = EncodeResponseFieldSection(response);
        byte[] frameBytes = Http3FrameWriter.WriteHeaders(encodedFieldSection);
        return new ResponseHeadersFrame(frameBytes, frameBytes.Length);
    }

    private static ValueTask<bool> WriteFixedResponseDataFramesAsync(
        QuicStream stream,
        Http3ServerResponse response,
        CancellationToken cancellationToken)
    {
        ReadOnlyMemory<byte> body = response.Body;
        int? dataFramePayloadSize = response.DataFramePayloadSize;
        int framePayloadSize = dataFramePayloadSize ?? ResponseDataFrameChunkSize;
        if (CanCacheSingleResponseDataFrame(response, framePayloadSize))
        {
            byte[]? cachedFrame = response.GetCachedSingleDataFrame();
            if (cachedFrame is null)
            {
                cachedFrame = response.CacheSingleDataFrame(Http3FrameWriter.WriteData(body.Span));
            }

            return WriteFinalFrameBytesAsync(stream, cachedFrame, cancellationToken);
        }

        return WriteFixedResponseDataFramesSlowAsync(stream, body, framePayloadSize, cancellationToken);
    }

    private static async ValueTask<bool> WriteFixedResponseDataFramesSlowAsync(
        QuicStream stream,
        ReadOnlyMemory<byte> body,
        int framePayloadSize,
        CancellationToken cancellationToken)
    {
        int offset = 0;
        while (offset < body.Length)
        {
            int count = Math.Min(framePayloadSize, body.Length - offset);
            bool isFinalFrame = offset + count == body.Length;
            byte[] dataFrameHeader = GetDataFrameHeader(count);
            if (!await WriteFrameBytesAsync(stream, dataFrameHeader, cancellationToken).ConfigureAwait(false))
            {
                return false;
            }

            int payloadOffset = 0;
            while (payloadOffset < count)
            {
                int writeCount = Math.Min(ResponseWriteChunkSize, count - payloadOffset);
                ReadOnlyMemory<byte> chunk = body.Slice(offset + payloadOffset, writeCount);
                bool isFinalWrite = isFinalFrame && payloadOffset + writeCount == count;
                bool written = isFinalWrite
                    ? await stream.TryWriteFinalAsync(chunk, cancellationToken).ConfigureAwait(false)
                    : await stream.TryWriteAsync(chunk, cancellationToken).ConfigureAwait(false);
                if (!written)
                {
                    return false;
                }

                payloadOffset += writeCount;
            }

            offset += count;
        }

        return true;
    }

    private static bool CanCacheSingleResponseDataFrame(Http3ServerResponse response, int framePayloadSize)
    {
        return response.CacheEncodedHeaders
            && response.StreamingBody is null
            && response.Body.Length <= framePayloadSize
            && response.Body.Length <= ResponseWriteChunkSize;
    }

    private void EmitResponseDataFrames(
        QuicStream stream,
        ReadOnlyMemory<byte> body,
        int? dataFramePayloadSize)
    {
        int framePayloadSize = dataFramePayloadSize ?? ResponseDataFrameChunkSize;
        int offset = 0;
        while (offset < body.Length)
        {
            int count = Math.Min(framePayloadSize, body.Length - offset);
            EmitFrame(Http3DiagnosticKind.FrameSent, stream.Id, Http3FrameType.Data, count);
            offset += count;
        }
    }

    private async ValueTask<bool> WriteStreamingResponseDataFramesAsync(
        QuicStream stream,
        IAsyncEnumerable<ReadOnlyMemory<byte>> body,
        int? dataFramePayloadSize,
        CancellationToken cancellationToken)
    {
        await using IAsyncEnumerator<ReadOnlyMemory<byte>> enumerator = body.GetAsyncEnumerator(cancellationToken);
        while (await enumerator.MoveNextAsync().ConfigureAwait(false))
        {
            ReadOnlyMemory<byte> current = enumerator.Current;
            int framePayloadSize = dataFramePayloadSize ?? ResponseDataFrameChunkSize;
            int offset = 0;
            while (offset < current.Length)
            {
                int count = Math.Min(framePayloadSize, current.Length - offset);
                byte[] dataFrameHeader = GetDataFrameHeader(count);
                if (!await WriteFrameBytesAsync(stream, dataFrameHeader, cancellationToken).ConfigureAwait(false))
                {
                    return false;
                }

                int payloadOffset = 0;
                while (payloadOffset < count)
                {
                    int writeCount = Math.Min(ResponseWriteChunkSize, count - payloadOffset);
                    if (!await stream.TryWriteAsync(
                        current.Slice(offset + payloadOffset, writeCount),
                        cancellationToken).ConfigureAwait(false))
                    {
                        return false;
                    }

                    payloadOffset += writeCount;
                }

                EmitFrame(Http3DiagnosticKind.FrameSent, stream.Id, Http3FrameType.Data, count);
                offset += count;
            }
        }

        if (!await WriteFinalFrameBytesAsync(stream, EmptyDataFrame, cancellationToken).ConfigureAwait(false))
        {
            return false;
        }

        EmitFrame(Http3DiagnosticKind.FrameSent, stream.Id, Http3FrameType.Data, 0);
        return true;
    }

    private static ValueTask<bool> WriteFrameBytesAsync(
        QuicStream stream,
        byte[] frameBytes,
        CancellationToken cancellationToken)
    {
        if (frameBytes.Length <= ResponseWriteChunkSize)
        {
            return stream.TryWriteAsync(frameBytes, cancellationToken);
        }

        return WriteFrameBytesSlowAsync(stream, frameBytes, cancellationToken);
    }

    private static async ValueTask<bool> WriteFrameBytesSlowAsync(
        QuicStream stream,
        byte[] frameBytes,
        CancellationToken cancellationToken)
    {
        int offset = 0;
        while (offset < frameBytes.Length)
        {
            int count = Math.Min(ResponseWriteChunkSize, frameBytes.Length - offset);
            if (!await stream.TryWriteAsync(frameBytes.AsMemory(offset, count), cancellationToken).ConfigureAwait(false))
            {
                return false;
            }

            offset += count;
        }

        return true;
    }

    private static ValueTask<bool> WriteFinalFrameBytesAsync(
        QuicStream stream,
        byte[] frameBytes,
        CancellationToken cancellationToken)
        => WriteFinalFrameBytesAsync(stream, frameBytes.AsMemory(), cancellationToken);

    private static ValueTask<bool> WriteFinalFrameBytesAsync(
        QuicStream stream,
        ReadOnlyMemory<byte> frameBytes,
        CancellationToken cancellationToken)
    {
        if (frameBytes.IsEmpty)
        {
            return new ValueTask<bool>(true);
        }

        if (frameBytes.Length <= ResponseWriteChunkSize)
        {
            return stream.TryWriteFinalAsync(frameBytes, cancellationToken);
        }

        return WriteFinalFrameBytesSlowAsync(stream, frameBytes, cancellationToken);
    }

    private static async ValueTask<bool> WriteFinalFrameBytesSlowAsync(
        QuicStream stream,
        ReadOnlyMemory<byte> frameBytes,
        CancellationToken cancellationToken)
    {
        int offset = 0;
        while (offset < frameBytes.Length)
        {
            int count = Math.Min(ResponseWriteChunkSize, frameBytes.Length - offset);
            if (offset + count == frameBytes.Length)
            {
                if (!await stream.TryWriteFinalAsync(frameBytes.Slice(offset, count), cancellationToken).ConfigureAwait(false))
                {
                    return false;
                }
            }
            else
            {
                if (!await stream.TryWriteAsync(frameBytes.Slice(offset, count), cancellationToken).ConfigureAwait(false))
                {
                    return false;
                }
            }

            offset += count;
        }

        return true;
    }

    private async ValueTask<bool> WriteGoAwayAsync(
        QuicStream controlStream,
        ulong streamId,
        CancellationToken cancellationToken)
    {
        byte[] goAwayFrame = Http3FrameWriter.WriteGoAway(streamId);
        if (!await WriteFrameBytesAsync(controlStream, goAwayFrame, cancellationToken).ConfigureAwait(false))
        {
            return false;
        }

        EmitFrame(Http3DiagnosticKind.FrameSent, controlStream.Id, Http3FrameType.GoAway, goAwayFrame.Length);
        return true;
    }

    internal static IReadOnlyList<QPackFieldLine> BuildResponseHeaders(Http3ServerResponse response)
    {
        int headerCount = 1;
        foreach (QPackFieldLine header in response.Headers)
        {
            if (header.Name != ":status")
            {
                headerCount++;
            }
        }

        QPackFieldLine[] headers = new QPackFieldLine[headerCount];
        headers[0] = new QPackFieldLine(":status", GetResponseStatusCodeString(response.StatusCode));

        int index = 1;
        foreach (QPackFieldLine header in response.Headers)
        {
            if (header.Name == ":status")
            {
                continue;
            }

            headers[index++] = header;
        }

        return headers;
    }

    internal static byte[] EncodeResponseFieldSection(Http3ServerResponse response)
    {
        string statusCode = GetResponseStatusCodeString(response.StatusCode);
        QPackFieldLine statusHeader = new(":status", statusCode);
        int length = GetIntegerEncodedLength(0, FieldSectionRequiredInsertCountPrefixBits)
            + GetIntegerEncodedLength(0, FieldSectionBasePrefixBits)
            + GetResponseHeaderLength(statusHeader);
        foreach (QPackFieldLine header in response.Headers)
        {
            if (header.Name == ":status")
            {
                continue;
            }

            length = checked(length + GetResponseHeaderLength(header));
        }

        byte[] encoded = new byte[length];
        int offset = 0;
        WriteInteger(encoded, ref offset, 0, FieldSectionRequiredInsertCountPrefixBits);
        WriteInteger(encoded, ref offset, 0, FieldSectionBasePrefixBits);
        WriteResponseHeader(encoded, ref offset, statusHeader);

        foreach (QPackFieldLine header in response.Headers)
        {
            if (header.Name == ":status")
            {
                continue;
            }

            WriteResponseHeader(encoded, ref offset, header);
        }

        return encoded;
    }

    internal static byte[] EncodeResponseFieldSection(IReadOnlyList<QPackFieldLine> headers)
    {
        byte[] encoded = new byte[GetResponseFieldSectionLength(headers)];
        int offset = 0;
        WriteInteger(encoded, ref offset, 0, FieldSectionRequiredInsertCountPrefixBits);
        WriteInteger(encoded, ref offset, 0, FieldSectionBasePrefixBits);

        foreach (QPackFieldLine header in headers)
        {
            WriteResponseHeader(encoded, ref offset, header);
        }

        return encoded;
    }

    private static string[] CreateResponseStatusCodeStrings()
    {
        string[] statusCodes = new string[MaximumResponseStatusCode - MinimumResponseStatusCode + 1];
        for (int statusCode = MinimumResponseStatusCode; statusCode <= MaximumResponseStatusCode; statusCode++)
        {
            statusCodes[statusCode - MinimumResponseStatusCode] = statusCode.ToString();
        }

        return statusCodes;
    }

    private static string GetResponseStatusCodeString(int statusCode)
    {
        if (statusCode is >= MinimumResponseStatusCode and <= MaximumResponseStatusCode)
        {
            return ResponseStatusCodeStrings[statusCode - MinimumResponseStatusCode];
        }

        return statusCode.ToString();
    }

    private static int GetResponseFieldSectionLength(IReadOnlyList<QPackFieldLine> headers)
    {
        int length = GetIntegerEncodedLength(0, FieldSectionRequiredInsertCountPrefixBits)
            + GetIntegerEncodedLength(0, FieldSectionBasePrefixBits);
        foreach (QPackFieldLine header in headers)
        {
            length = checked(length + GetResponseHeaderLength(header));
        }

        return length;
    }

    private static int GetResponseHeaderLength(QPackFieldLine header)
    {
        if (header.Name == ":status")
        {
            int valueByteCount = HeaderTextEncoding.GetByteCount(header.Value);
            return GetLiteralWithStaticNameReferenceLength(StatusStaticNameIndex, valueByteCount);
        }

        int staticFieldIndex = FindStaticFieldLineIndex(header);
        if (staticFieldIndex >= 0)
        {
            return GetIntegerEncodedLength(checked((ulong)staticFieldIndex), IndexedFieldPrefixBits);
        }

        int staticNameIndex = FindStaticNameIndex(header.Name);
        if (staticNameIndex >= 0)
        {
            int staticNameValueByteCount = HeaderTextEncoding.GetByteCount(header.Value);
            return GetLiteralWithStaticNameReferenceLength(staticNameIndex, staticNameValueByteCount);
        }

        int nameByteCount = HeaderTextEncoding.GetByteCount(header.Name);
        int literalValueByteCount = HeaderTextEncoding.GetByteCount(header.Value);
        return checked(
            GetIntegerEncodedLength(checked((ulong)nameByteCount), LiteralNamePrefixBits - 1)
            + nameByteCount
            + GetIntegerEncodedLength(checked((ulong)literalValueByteCount), StringLiteralPrefixBits - 1)
            + literalValueByteCount);
    }

    private static void WriteResponseHeader(byte[] encoded, ref int offset, QPackFieldLine header)
    {
        if (header.Name == ":status")
        {
            WriteLiteralWithStaticNameReference(encoded, ref offset, StatusStaticNameIndex, header.Value);
            return;
        }

        int staticFieldIndex = FindStaticFieldLineIndex(header);
        if (staticFieldIndex >= 0)
        {
            WriteInteger(encoded, ref offset, checked((ulong)staticFieldIndex), IndexedFieldPrefixBits, StaticIndexedFieldPrefix);
            return;
        }

        int staticNameIndex = FindStaticNameIndex(header.Name);
        if (staticNameIndex >= 0)
        {
            WriteLiteralWithStaticNameReference(encoded, ref offset, staticNameIndex, header.Value);
            return;
        }

        WriteInteger(encoded, ref offset, checked((ulong)HeaderTextEncoding.GetByteCount(header.Name)), LiteralNamePrefixBits - 1, LiteralWithLiteralNamePrefix);
        WriteRawString(encoded, ref offset, header.Name);
        WriteStringLiteral(encoded, ref offset, header.Value);
    }

    private static int GetLiteralWithStaticNameReferenceLength(int staticNameIndex, int valueByteCount)
    {
        return checked(
            GetIntegerEncodedLength(checked((ulong)staticNameIndex), StaticNameReferencePrefixBits)
            + GetIntegerEncodedLength(checked((ulong)valueByteCount), StringLiteralPrefixBits - 1)
            + valueByteCount);
    }

    internal static void EmitStreamOpenedDiagnostic(
        IHttp3DiagnosticsSink? sink,
        string role,
        long streamId,
        Http3StreamKind streamKind)
    {
        if (!IsDiagnosticEnabled(sink, Http3DiagnosticKind.StreamOpened))
        {
            return;
        }

        sink!.Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.StreamOpened)
        {
            Role = role,
            StreamId = streamId,
            StreamKind = streamKind,
        });
    }

    internal static void EmitFrameDiagnostic(
        IHttp3DiagnosticsSink? sink,
        Http3DiagnosticKind kind,
        string role,
        long streamId,
        Http3FrameType frameType,
        int payloadLength)
    {
        if (!IsDiagnosticEnabled(sink, kind))
        {
            return;
        }

        sink!.Emit(new Http3DiagnosticEvent(kind)
        {
            Role = role,
            StreamId = streamId,
            FrameType = frameType,
            RawFrameType = checked((ulong)frameType),
            PayloadLength = payloadLength,
        });
    }

    internal static void EmitRequestStartedDiagnostic(
        IHttp3DiagnosticsSink? sink,
        string role,
        long streamId,
        string method,
        string path)
    {
        if (!IsDiagnosticEnabled(sink, Http3DiagnosticKind.RequestStarted))
        {
            return;
        }

        if (sink is IHttp3LifecycleDiagnosticsSink lifecycleSink)
        {
            lifecycleSink.EmitRequestStarted(role, streamId, method, path);
            return;
        }

        sink!.Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.RequestStarted)
        {
            Role = role,
            StreamId = streamId,
            Method = method,
            Path = path,
        });
    }

    internal static void EmitResponseStartedDiagnostic(
        IHttp3DiagnosticsSink? sink,
        string role,
        long streamId,
        int statusCode)
    {
        if (!IsDiagnosticEnabled(sink, Http3DiagnosticKind.ResponseStarted))
        {
            return;
        }

        if (sink is IHttp3LifecycleDiagnosticsSink lifecycleSink)
        {
            lifecycleSink.EmitResponseStarted(role, streamId, statusCode);
            return;
        }

        sink!.Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.ResponseStarted)
        {
            Role = role,
            StreamId = streamId,
            StatusCode = statusCode,
        });
    }

    internal static void EmitResponseCompletedDiagnostic(
        IHttp3DiagnosticsSink? sink,
        string role,
        long streamId,
        int statusCode,
        int payloadLength)
    {
        if (!IsDiagnosticEnabled(sink, Http3DiagnosticKind.ResponseCompleted))
        {
            return;
        }

        if (sink is IHttp3LifecycleDiagnosticsSink lifecycleSink)
        {
            lifecycleSink.EmitResponseCompleted(role, streamId, statusCode, payloadLength);
            return;
        }

        sink!.Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.ResponseCompleted)
        {
            Role = role,
            StreamId = streamId,
            StatusCode = statusCode,
            PayloadLength = payloadLength,
        });
    }

    internal static void EmitRequestCompletedDiagnostic(
        IHttp3DiagnosticsSink? sink,
        string role,
        long streamId,
        string method,
        string path,
        int statusCode,
        int payloadLength)
    {
        if (!IsDiagnosticEnabled(sink, Http3DiagnosticKind.RequestCompleted))
        {
            return;
        }

        if (sink is IHttp3LifecycleDiagnosticsSink lifecycleSink)
        {
            lifecycleSink.EmitRequestCompleted(role, streamId, method, path, statusCode, payloadLength);
            return;
        }

        sink!.Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.RequestCompleted)
        {
            Role = role,
            StreamId = streamId,
            Method = method,
            Path = path,
            StatusCode = statusCode,
            PayloadLength = payloadLength,
        });
    }

    internal static void EmitStreamClosedDiagnostic(
        IHttp3DiagnosticsSink? sink,
        string role,
        long streamId,
        Http3StreamKind streamKind)
    {
        if (!IsDiagnosticEnabled(sink, Http3DiagnosticKind.StreamClosed))
        {
            return;
        }

        sink!.Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.StreamClosed)
        {
            Role = role,
            StreamId = streamId,
            StreamKind = streamKind,
        });
    }

    private static bool IsDiagnosticEnabled(IHttp3DiagnosticsSink? sink, Http3DiagnosticKind kind)
    {
        if (sink?.IsEnabled != true)
        {
            return false;
        }

        return sink is not IHttp3DiagnosticKindFilter filter || filter.IsEnabledFor(kind);
    }

    private static void WriteLiteralWithStaticNameReference(byte[] destination, ref int offset, int staticNameIndex, string value)
    {
        WriteInteger(destination, ref offset, checked((ulong)staticNameIndex), StaticNameReferencePrefixBits, LiteralWithStaticNameReferencePrefix);
        WriteStringLiteral(destination, ref offset, value);
    }

    private static void WriteStringLiteral(byte[] destination, ref int offset, string value)
    {
        WriteInteger(destination, ref offset, checked((ulong)HeaderTextEncoding.GetByteCount(value)), StringLiteralPrefixBits - 1);
        WriteRawString(destination, ref offset, value);
    }

    private static void WriteRawString(byte[] destination, ref int offset, string value)
    {
        int byteCount = HeaderTextEncoding.GetByteCount(value);
        int bytesWritten = HeaderTextEncoding.GetBytes(value.AsSpan(), destination.AsSpan(offset, byteCount));
        offset += bytesWritten;
    }

    private static void WriteInteger(byte[] destination, ref int offset, ulong value, int prefixBitCount, byte prefixBits = 0)
    {
        offset += WriteInteger(destination.AsSpan(offset), value, prefixBitCount, prefixBits);
    }

    private static int WriteInteger(Span<byte> destination, ulong value, int prefixBitCount, byte prefixBits = 0)
    {
        if (prefixBitCount is < 1 or > QPackIntegerMaxPrefixBitCount)
        {
            throw new ArgumentOutOfRangeException(nameof(prefixBitCount));
        }

        if (value > QPackIntegerMaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(value));
        }

        byte mask = prefixBitCount == QPackIntegerMaxPrefixBitCount
            ? byte.MaxValue
            : (byte)((1 << prefixBitCount) - 1);
        int bytesWritten = 0;
        if (value < mask)
        {
            destination[bytesWritten++] = (byte)(prefixBits | value);
            return bytesWritten;
        }

        destination[bytesWritten++] = (byte)(prefixBits | mask);

        value -= mask;
        while (value >= QPackIntegerContinuationThreshold)
        {
            destination[bytesWritten++] = (byte)((value & QPackIntegerContinuationValueMask) | QPackIntegerContinuationFlag);
            value >>= QPackIntegerContinuationShift;
        }

        destination[bytesWritten++] = (byte)value;
        return bytesWritten;
    }

    private static int GetIntegerEncodedLength(ulong value, int prefixBitCount)
    {
        if (prefixBitCount is < 1 or > QPackIntegerMaxPrefixBitCount)
        {
            throw new ArgumentOutOfRangeException(nameof(prefixBitCount));
        }

        if (value > QPackIntegerMaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(value));
        }

        byte mask = prefixBitCount == QPackIntegerMaxPrefixBitCount
            ? byte.MaxValue
            : (byte)((1 << prefixBitCount) - 1);
        if (value < mask)
        {
            return 1;
        }

        int length = 1;
        value -= mask;
        while (value >= QPackIntegerContinuationThreshold)
        {
            length++;
            value >>= QPackIntegerContinuationShift;
        }

        return length + 1;
    }

    private static int FindStaticFieldLineIndex(QPackFieldLine fieldLine)
    {
        return StaticFieldLineIndexes.TryGetValue(fieldLine, out int index)
            ? index
            : -1;
    }

    private static int FindStaticNameIndex(string name)
    {
        return StaticNameIndexes.TryGetValue(name, out int index)
            ? index
            : -1;
    }

    private static Dictionary<QPackFieldLine, int> BuildStaticFieldLineIndexes()
    {
        Dictionary<QPackFieldLine, int> indexes = new(QPackStaticTable.Count);
        for (int index = 0; index < QPackStaticTable.Count; index++)
        {
            if (QPackStaticTable.TryGet(index, out QPackFieldLine candidate)
                && !indexes.ContainsKey(candidate))
            {
                indexes.Add(candidate, index);
            }
        }

        return indexes;
    }

    private static Dictionary<string, int> BuildStaticNameIndexes()
    {
        Dictionary<string, int> indexes = new(QPackStaticTable.Count, StringComparer.Ordinal);
        for (int index = 0; index < QPackStaticTable.Count; index++)
        {
            if (QPackStaticTable.TryGet(index, out QPackFieldLine candidate)
                && !indexes.ContainsKey(candidate.Name))
            {
                indexes.Add(candidate.Name, index);
            }
        }

        return indexes;
    }

    private static Http3ServerResponse CreateBadRequestResponse()
    {
        return new Http3ServerResponse(
            400,
            "Bad Request"u8.ToArray(),
            [new QPackFieldLine("content-type", "text/plain")]);
    }

    private static async ValueTask WriteStreamTypeAsync(
        QuicStream stream,
        Http3StreamType streamType,
        CancellationToken cancellationToken)
    {
        byte[] encoded = EncodeVariableLengthInteger(checked((ulong)streamType));
        await stream.WriteAsync(encoded, 0, encoded.Length, cancellationToken).ConfigureAwait(false);
    }

    private static byte[] WriteFrameHeader(ulong frameType, int payloadLength)
    {
        if (payloadLength < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(payloadLength));
        }

        byte[] encoded = new byte[
            Http3VariableLengthInteger.GetEncodedLength(frameType)
            + Http3VariableLengthInteger.GetEncodedLength(checked((ulong)payloadLength))];
        int offset = 0;
        if (!Http3VariableLengthInteger.TryFormat(frameType, encoded.AsSpan(offset), out int typeBytesWritten))
        {
            throw new ArgumentOutOfRangeException(nameof(frameType));
        }

        offset += typeBytesWritten;
        if (!Http3VariableLengthInteger.TryFormat(checked((ulong)payloadLength), encoded.AsSpan(offset), out int lengthBytesWritten))
        {
            throw new ArgumentOutOfRangeException(nameof(payloadLength));
        }

        offset += lengthBytesWritten;
        if (offset != encoded.Length)
        {
            throw new InvalidOperationException("HTTP/3 frame header encoding length did not match the computed length.");
        }

        return encoded;
    }

    private static byte[] GetDataFrameHeader(int payloadLength)
    {
        return payloadLength switch
        {
            ResponseDataFrameChunkSize => ResponseDataFrameChunkDataFrameHeader,
            _ => WriteFrameHeader((ulong)Http3FrameType.Data, payloadLength),
        };
    }

    private static byte[] EncodeVariableLengthInteger(ulong value)
    {
        Span<byte> destination = stackalloc byte[Http3VariableLengthInteger.MaxEncodedLength];
        if (!Http3VariableLengthInteger.TryFormat(value, destination, out int bytesWritten))
        {
            throw new ArgumentOutOfRangeException(nameof(value));
        }

        return destination[..bytesWritten].ToArray();
    }

    private static void SuppressExpectedException(Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);
    }

    private sealed class ConnectionQPackState
    {
        private readonly object gate = new();
        private readonly TaskCompletionSource<Http3Settings> peerSettings =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly Dictionary<ulong, TaskCompletionSource<QPackFieldLine[]>> blockedRequests = [];
        private readonly QPackEncoder encoder;
        private readonly Http3FieldSectionDecodeCache decodedRequestHeaderCache = new();
        private QPackDecoder? decoder;
        private byte[] pendingEncoderStreamBytes = [];

        internal ConnectionQPackState(Http3Settings localSettings)
        {
            ArgumentNullException.ThrowIfNull(localSettings);

            encoder = new QPackEncoder(
                checked((int)localSettings.QPackMaxTableCapacity),
                checked((int)localSettings.QPackBlockedStreams));
        }

        public void SetPeerSettings(Http3Settings settings)
        {
            ArgumentNullException.ThrowIfNull(settings);

            lock (gate)
            {
                EnsureDecoder(settings);
            }

            peerSettings.TrySetResult(settings);
        }

        public ValueTask<IReadOnlyList<QPackFieldLine>> DecodeRequestHeadersAsync(
            ulong streamId,
            ReadOnlyMemory<byte> encodedFieldSection,
            CancellationToken cancellationToken)
        {
            Task<Http3Settings> settingsTask = peerSettings.Task;
            if (settingsTask.IsCompletedSuccessfully)
            {
                return DecodeRequestHeadersWithSettings(
                    streamId,
                    encodedFieldSection,
                    settingsTask.Result,
                    cancellationToken);
            }

            return DecodeRequestHeadersAfterSettingsAsync(streamId, encodedFieldSection, settingsTask, cancellationToken);
        }

        private async ValueTask<IReadOnlyList<QPackFieldLine>> DecodeRequestHeadersAfterSettingsAsync(
            ulong streamId,
            ReadOnlyMemory<byte> encodedFieldSection,
            Task<Http3Settings> settingsTask,
            CancellationToken cancellationToken)
        {
            Http3Settings settings = await settingsTask.WaitAsync(cancellationToken).ConfigureAwait(false);
            return await DecodeRequestHeadersWithSettings(streamId, encodedFieldSection, settings, cancellationToken).ConfigureAwait(false);
        }

        private ValueTask<IReadOnlyList<QPackFieldLine>> DecodeRequestHeadersWithSettings(
            ulong streamId,
            ReadOnlyMemory<byte> encodedFieldSection,
            Http3Settings settings,
            CancellationToken cancellationToken)
        {
            TaskCompletionSource<QPackFieldLine[]>? blockedCompletion = null;
            lock (gate)
            {
                EnsureDecoder(settings);
                if (decodedRequestHeaderCache.TryGet(encodedFieldSection.Span, out IReadOnlyList<QPackFieldLine>? cachedFieldLines))
                {
                    return new ValueTask<IReadOnlyList<QPackFieldLine>>(cachedFieldLines);
                }

                Http3FieldLineBuffer fieldLines = new();
                QPackFieldSectionDecodeStatus decoded = decoder!.DecodeFieldSection(streamId, encodedFieldSection, fieldLines);
                if (!decoded.IsBlocked)
                {
                    IReadOnlyList<QPackFieldLine> decodedFieldLines = fieldLines.CommitToReadOnlyList();
                    decodedRequestHeaderCache.Store(encodedFieldSection.Span, decodedFieldLines);
                    return new ValueTask<IReadOnlyList<QPackFieldLine>>(decodedFieldLines);
                }

                blockedCompletion = new TaskCompletionSource<QPackFieldLine[]>(TaskCreationOptions.RunContinuationsAsynchronously);
                blockedRequests[streamId] = blockedCompletion;
            }

            return AwaitBlockedFieldLinesAsync(blockedCompletion, cancellationToken);
        }

        private static async ValueTask<IReadOnlyList<QPackFieldLine>> AwaitBlockedFieldLinesAsync(
            TaskCompletionSource<QPackFieldLine[]> blockedCompletion,
            CancellationToken cancellationToken)
        {
            return await blockedCompletion.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
        }

        public void ProcessPeerEncoderStreamBytes(ReadOnlySpan<byte> bytes)
        {
            if (bytes.IsEmpty)
            {
                return;
            }

            lock (gate)
            {
                if (decoder is null)
                {
                    pendingEncoderStreamBytes = Append(pendingEncoderStreamBytes, bytes);
                    return;
                }

                CompleteUnblockedRequests(decoder.DecodeEncoderStream(bytes));
            }
        }

        public void ProcessPeerDecoderStreamBytes(ReadOnlySpan<byte> bytes)
        {
            if (bytes.IsEmpty)
            {
                return;
            }

            lock (gate)
            {
                encoder.DecodeDecoderStream(bytes);
            }
        }

        public void CompletePeerEncoderStream()
        {
            lock (gate)
            {
                if (decoder is null)
                {
                    EnsureDecoder(new Http3Settings());
                }

                CompleteUnblockedRequests(decoder!.CompleteEncoderStream());
            }
        }

        public void CompletePeerDecoderStream()
        {
            lock (gate)
            {
                encoder.CompleteDecoderStream();
            }
        }

        private void EnsureDecoder(Http3Settings settings)
        {
            if (decoder is not null)
            {
                return;
            }

            decoder = new QPackDecoder(
                checked((int)settings.QPackMaxTableCapacity),
                checked((int)settings.QPackBlockedStreams));
            if (pendingEncoderStreamBytes.Length != 0)
            {
                CompleteUnblockedRequests(decoder.DecodeEncoderStream(pendingEncoderStreamBytes));
                pendingEncoderStreamBytes = [];
            }
        }

        private void CompleteUnblockedRequests(QPackFieldSectionDecodeResult[] results)
        {
            foreach (QPackFieldSectionDecodeResult result in results)
            {
                if (blockedRequests.Remove(result.StreamId, out TaskCompletionSource<QPackFieldLine[]>? completion))
                {
                    completion.TrySetResult(result.FieldLines);
                }
            }
        }

        private static byte[] Append(byte[] pending, ReadOnlySpan<byte> source)
        {
            if (source.IsEmpty)
            {
                return pending;
            }

            byte[] combined = new byte[pending.Length + source.Length];
            pending.CopyTo(combined, 0);
            source.CopyTo(combined.AsSpan(pending.Length));
            return combined;
        }
    }

    private void EmitFrame(Http3DiagnosticKind kind, long streamId, Http3FrameType frameType, int payloadLength)
    {
        EmitFrameDiagnostic(diagnosticsSink, kind, "server", streamId, frameType, payloadLength);
    }

    private void EmitFrame(Http3DiagnosticKind kind, long streamId, Http3Frame frame)
    {
        if (!IsDiagnosticEnabled(diagnosticsSink, kind))
        {
            return;
        }

        diagnosticsSink!.Emit(new Http3DiagnosticEvent(kind)
        {
            Role = "server",
            StreamId = streamId,
            FrameType = Enum.IsDefined(typeof(Http3FrameType), (long)frame.Type) ? (Http3FrameType)frame.Type : null,
            RawFrameType = frame.Type,
            PayloadLength = frame.Payload.Length,
        });
    }

    private void EmitQPackBytesReceived(long streamId, Http3StreamKind streamKind, int payloadLength)
    {
        if (payloadLength == 0 || !IsDiagnosticEnabled(diagnosticsSink, Http3DiagnosticKind.QPackInstructionReceived))
        {
            return;
        }

        diagnosticsSink!.Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.QPackInstructionReceived)
        {
            Role = "server",
            StreamId = streamId,
            StreamKind = streamKind,
            PayloadLength = payloadLength,
            QPackInstruction = "bytes",
        });
    }

    private void EmitError(Exception exception)
    {
        if (!IsDiagnosticEnabled(diagnosticsSink, Http3DiagnosticKind.Error))
        {
            return;
        }

        diagnosticsSink!.Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.Error)
        {
            Role = "server",
            ErrorCode = exception is Http3Exception http3Exception
                ? http3Exception.ErrorCode.ToString()
                : exception.GetType().Name,
            Message = exception.Message,
        });
    }

    private readonly record struct ResponseHeadersFrame(byte[] FrameBytes, int FrameLength);
}
