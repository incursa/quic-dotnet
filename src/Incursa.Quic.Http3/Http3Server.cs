// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers;
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
    // ResponseDataFrameChunkSize caps HTTP/3 DATA payloads, while
    // ResponseWriteChunkSize only caps each QUIC write call. Keeping them
    // separate preserves frame boundaries and keeps the final-frame path able
    // to use WriteFinalAsync on the last chunk.
    private const int ResponseWriteChunkSize = 1024;
    private const int ResponseDataFrameChunkSize = 16 * 1024;
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
                if (IsDiagnosticEnabled(diagnosticsSink))
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
                if (IsDiagnosticEnabled(diagnosticsSink))
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
                if (IsDiagnosticEnabled(diagnosticsSink))
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
        if (IsDiagnosticEnabled(diagnosticsSink))
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
        if (IsDiagnosticEnabled(diagnosticsSink))
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
        if (IsDiagnosticEnabled(diagnosticsSink))
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
            QuicStream stream = await connection.AcceptInboundStreamAsync(cancellationToken).ConfigureAwait(false);
            Http3StreamKind streamKind = stream.Type == QuicStreamType.Bidirectional
                ? Http3StreamKind.Request
                : Http3StreamKind.Unknown;
            if (stream.Type == QuicStreamType.Bidirectional)
            {
                lock (dispatcherGate)
                {
                    dispatcher.RegisterBidirectionalStream(checked((ulong)stream.Id));
                }
            }

            EmitStreamOpenedDiagnostic(diagnosticsSink, "server", stream.Id, streamKind);
            _ = stream.Type == QuicStreamType.Bidirectional
                ? HandleRequestStreamAsync(connection, stream, controlStream, qpackState, cancellationToken)
                : ObservePeerUnidirectionalStreamAsync(connection, stream, dispatcher, dispatcherGate, qpackState, cancellationToken);
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
            byte[] buffer = new byte[readBufferSize];
            byte[] pendingStreamType = [];
            Http3StreamKind streamKind = Http3StreamKind.Unknown;
            try
            {
                lock (dispatcherGate)
                {
                    dispatcher.RegisterUnidirectionalStream(checked((ulong)stream.Id));
                }

                while (true)
                {
                    int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false);
                    if (bytesRead == 0)
                    {
                        lock (dispatcherGate)
                        {
                            dispatcher.ReceiveUnidirectionalStreamTypeBytes(
                                checked((ulong)stream.Id),
                                pendingStreamType,
                                endOfStream: true);
                        }

                        return;
                    }

                    pendingStreamType = Append(pendingStreamType, buffer.AsSpan(0, bytesRead));
                    if (!Http3VariableLengthInteger.TryParse(pendingStreamType, out _, out int bytesConsumed))
                    {
                        continue;
                    }

                    byte[] streamTypeBytes = pendingStreamType.AsSpan(0, bytesConsumed).ToArray();
                    byte[] initialPayload = pendingStreamType.AsSpan(bytesConsumed).ToArray();
                    Http3StreamInfo streamInfo;
                    lock (dispatcherGate)
                    {
                        streamInfo = dispatcher.ReceiveUnidirectionalStreamTypeBytes(
                            checked((ulong)stream.Id),
                            streamTypeBytes);
                    }

                    streamKind = streamInfo.Kind;
                    EmitStreamOpenedDiagnostic(diagnosticsSink, "server", stream.Id, streamKind);

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
            }
        }
    }

    private async ValueTask ObservePeerUnidirectionalPayloadAsync(
        QuicStream stream,
        Http3StreamDispatcher dispatcher,
        object dispatcherGate,
        ConnectionQPackState qpackState,
        Http3StreamKind streamKind,
        byte[] initialPayload,
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
        byte[] initialPayload,
        byte[] buffer,
        CancellationToken cancellationToken)
    {
        Http3FrameReader frameReader = new();
        ProcessPeerControlBytes(frameReader, initialPayload, stream.Id, dispatcher, dispatcherGate, qpackState);

        while (true)
        {
            int bytesRead = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken).ConfigureAwait(false);
            if (bytesRead == 0)
            {
                ProcessPeerControlFrames(frameReader.Complete(), stream.Id, dispatcher, dispatcherGate, qpackState);
                throw new Http3Exception(Http3ErrorCode.ClosedCriticalStream, "The HTTP/3 control stream was closed.");
            }

            ProcessPeerControlBytes(frameReader, buffer.AsSpan(0, bytesRead), stream.Id, dispatcher, dispatcherGate, qpackState);
        }
    }

    private async ValueTask DrainPeerQPackStreamAsync(
        QuicStream stream,
        Http3StreamKind streamKind,
        byte[] initialPayload,
        byte[] buffer,
        ConnectionQPackState qpackState,
        CancellationToken cancellationToken)
    {
        EmitQPackBytesReceived(stream.Id, streamKind, initialPayload.Length);
        if (streamKind == Http3StreamKind.QPackEncoder)
        {
            qpackState.ProcessPeerEncoderStreamBytes(initialPayload);
        }
        else
        {
            qpackState.ProcessPeerDecoderStreamBytes(initialPayload);
        }

        while (true)
        {
            int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false);
            if (bytesRead == 0)
            {
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
            int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false);
            if (bytesRead == 0)
            {
                return;
            }
        }
    }

    private async Task HandleRequestStreamAsync(
        QuicConnection connection,
        QuicStream stream,
        QuicStream controlStream,
        ConnectionQPackState qpackState,
        CancellationToken cancellationToken)
    {
        await using (stream.ConfigureAwait(false))
        {
            long requestStartedTimestamp = 0;
            bool requestStarted = false;
            try
            {
                Http3Request request = await ReadRequestAsync(stream, qpackState, cancellationToken).ConfigureAwait(false);
                requestStartedTimestamp = Http3Metrics.GetTimestamp();
                requestStarted = true;
                Http3Metrics.RecordRequestStarted("server");
                EmitRequestStartedDiagnostic(diagnosticsSink, "server", stream.Id, request.Method, request.Path);
                if (TryGetWebSocketHandler(request, out IHttp3WebSocketHandler? tunnelHandler))
                {
                    Http3ServerResponse acceptedResponse = new(
                        200,
                        ReadOnlyMemory<byte>.Empty,
                        webSocketAcceptResponseHeadersSelector?.Invoke(request));
                    await WriteTunnelResponseHeadersAsync(stream, acceptedResponse, cancellationToken).ConfigureAwait(false);
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

                Http3ServerResponse response = request.Protocol is not null && !Http3ExtendedConnect.IsSupportedProtocol(request.Protocol)
                    ? Http3ExtendedConnect.CreateUnsupportedProtocolResponse(request.Protocol)
                    : await handler.HandleAsync(request, cancellationToken).ConfigureAwait(false);
                await WriteResponseAsync(stream, response, cancellationToken).ConfigureAwait(false);
                if (response.SendGoAwayAfterResponse)
                {
                    await WriteGoAwayAsync(controlStream, checked((ulong)stream.Id), cancellationToken).ConfigureAwait(false);
                }

                if (response.CloseConnectionAfterResponse)
                {
                    await connection.CloseAsync(0, cancellationToken).ConfigureAwait(false);
                }

                Http3Metrics.RecordRequestCompleted("server", response.StatusCode, requestStartedTimestamp);
                EmitResponseCompletedDiagnostic(diagnosticsSink, "server", stream.Id, response.StatusCode, response.Body.Length);
                EmitRequestCompletedDiagnostic(diagnosticsSink, "server", stream.Id, request.Method, request.Path, response.StatusCode, response.Body.Length);
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
            finally
            {
                EmitStreamClosedDiagnostic(diagnosticsSink, "server", stream.Id, Http3StreamKind.Request);
            }
        }
    }

    private bool TryGetWebSocketHandler(Http3Request request, out IHttp3WebSocketHandler? tunnelHandler)
    {
        tunnelHandler = null;
        if (!Http3ExtendedConnect.IsSupportedProtocol(request.Protocol) || webSocketHandler is null)
        {
            return false;
        }

        tunnelHandler = webSocketHandler;
        return true;
    }

    private async ValueTask<Http3Request> ReadRequestAsync(
        QuicStream stream,
        ConnectionQPackState qpackState,
        CancellationToken cancellationToken)
    {
        Http3FrameReader frameReader = new(ValidateRequestStreamFrameType);
        Http3RequestMessageValidator validator = new();
        ArrayBufferWriter<byte>? body = null;
        // CONTEXT: Request read buffering
        // SEE: spec:REQ-QUIC-RFC9114-S4-0002
        // SEE: code:src/Incursa.Quic.Http3/Http3FrameReader.cs#Read
        // SEE: code:src/Incursa.Quic.Http3/Http3RequestMessageValidator.cs#ReceiveData
        // A pooled buffer is used here because frame parsing spans multiple
        // awaited reads and the frame reader may hold partial bytes until it
        // can complete a frame.
        byte[] buffer = ArrayPool<byte>.Shared.Rent(readBufferSize);

        try
        {
            while (true)
            {
                int bytesRead = await stream.ReadAsync(buffer, 0, readBufferSize, cancellationToken).ConfigureAwait(false);
                if (bytesRead == 0)
                {
                    foreach (Http3Frame frame in frameReader.Complete())
                    {
                        EmitFrame(Http3DiagnosticKind.FrameReceived, stream.Id, frame);
                        body = await ProcessRequestFrameAsync(frame, validator, body, stream.Id, qpackState, cancellationToken).ConfigureAwait(false);
                    }

                    break;
                }

                foreach (Http3Frame frame in frameReader.Read(buffer.AsSpan(0, bytesRead)))
                {
                    EmitFrame(Http3DiagnosticKind.FrameReceived, stream.Id, frame);
                    body = await ProcessRequestFrameAsync(frame, validator, body, stream.Id, qpackState, cancellationToken).ConfigureAwait(false);
                }

                if (TryCreateHeadersOnlyRequest(validator.Headers, out Http3Request request))
                {
                    return request;
                }
            }

            validator.Complete();
            IReadOnlyList<QPackFieldLine>? headers = validator.Headers;
            if (headers is null)
            {
                throw new Http3Exception(Http3ErrorCode.MessageError, "The HTTP/3 request did not contain a HEADERS frame.");
            }

            return CreateRequest(headers, body?.WrittenMemory ?? ReadOnlyMemory<byte>.Empty);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer, clearArray: false);
        }
    }

    private static bool TryCreateHeadersOnlyRequest(
        IReadOnlyList<QPackFieldLine>? headers,
        out Http3Request request)
    {
        request = null!;
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

        request = new Http3Request(result.Method!, result.Scheme ?? string.Empty, result.Authority ?? string.Empty, result.Path ?? string.Empty, result.Protocol, headers, ReadOnlyMemory<byte>.Empty);
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

                if (IsDiagnosticEnabled(diagnosticsSink))
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

    private static Http3Request CreateRequest(IReadOnlyList<QPackFieldLine> headers, ReadOnlyMemory<byte> body)
    {
        Http3HeaderValidationResult result = Http3HeaderValidator.ValidateRequestHeaders(headers, checked((ulong)body.Length));
        return new Http3Request(result.Method!, result.Scheme ?? string.Empty, result.Authority ?? string.Empty, result.Path ?? string.Empty, result.Protocol, headers, body);
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
            await WriteResponseAsync(stream, response, cancellationToken).ConfigureAwait(false);
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

    private async ValueTask WriteResponseAsync(
        QuicStream stream,
        Http3ServerResponse response,
        CancellationToken cancellationToken)
    {
        byte[] encodedFieldSection = EncodeResponseFieldSection(BuildResponseHeaders(response));
        int headersFrameLength = Http3FrameWriter.GetFrameLength((ulong)Http3FrameType.Headers, encodedFieldSection.Length);
        if (response.StreamingBody is not null)
        {
            byte[] headersFrame = Http3FrameWriter.WriteHeaders(encodedFieldSection);
            await WriteFrameBytesAsync(stream, headersFrame, cancellationToken).ConfigureAwait(false);
        }
        else if (response.Body.IsEmpty)
        {
            byte[] headersFrame = Http3FrameWriter.WriteHeaders(encodedFieldSection);
            await WriteFinalFrameBytesAsync(stream, headersFrame, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            await WriteBufferedResponseFramesAsync(
                stream,
                encodedFieldSection,
                headersFrameLength,
                response.Body,
                response.DataFramePayloadSize,
                cancellationToken).ConfigureAwait(false);
        }

        EmitFrame(Http3DiagnosticKind.FrameSent, stream.Id, Http3FrameType.Headers, headersFrameLength);
        EmitResponseStartedDiagnostic(diagnosticsSink, "server", stream.Id, response.StatusCode);

        if (response.StreamingBody is not null)
        {
            await WriteStreamingResponseDataFramesAsync(stream, response.StreamingBody, response.DataFramePayloadSize, cancellationToken).ConfigureAwait(false);
        }
        else if (!response.Body.IsEmpty)
        {
            EmitResponseDataFrames(stream, response.Body, response.DataFramePayloadSize);
        }
    }

    private async ValueTask WriteTunnelResponseHeadersAsync(
        QuicStream stream,
        Http3ServerResponse response,
        CancellationToken cancellationToken)
    {
        byte[] encodedFieldSection = EncodeResponseFieldSection(BuildResponseHeaders(response));
        byte[] headersFrame = Http3FrameWriter.WriteHeaders(encodedFieldSection);
        await WriteFrameBytesAsync(stream, headersFrame, cancellationToken).ConfigureAwait(false);
        EmitFrame(Http3DiagnosticKind.FrameSent, stream.Id, Http3FrameType.Headers, headersFrame.Length);
        EmitResponseStartedDiagnostic(diagnosticsSink, "server", stream.Id, response.StatusCode);
    }

    private static async ValueTask WriteBufferedResponseFramesAsync(
        QuicStream stream,
        byte[] encodedFieldSection,
        int headersFrameLength,
        ReadOnlyMemory<byte> body,
        int? dataFramePayloadSize,
        CancellationToken cancellationToken)
    {
        int framePayloadSize = dataFramePayloadSize ?? ResponseDataFrameChunkSize;
        int bufferedLength = headersFrameLength;
        for (int sizingOffset = 0; sizingOffset < body.Length;)
        {
            int count = Math.Min(framePayloadSize, body.Length - sizingOffset);
            bufferedLength = checked(bufferedLength + Http3FrameWriter.GetFrameLength((ulong)Http3FrameType.Data, count));
            sizingOffset += count;
        }

        ArrayBufferWriter<byte> writer = new(bufferedLength);
        Http3FrameWriter.WriteHeaders(writer, encodedFieldSection);

        int offset = 0;
        while (offset < body.Length)
        {
            int count = Math.Min(framePayloadSize, body.Length - offset);
            Http3FrameWriter.WriteData(writer, body.Span.Slice(offset, count));
            offset += count;
        }

        await WriteFinalFrameBytesAsync(stream, writer.WrittenMemory, cancellationToken).ConfigureAwait(false);
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

    private async ValueTask WriteStreamingResponseDataFramesAsync(
        QuicStream stream,
        IAsyncEnumerable<ReadOnlyMemory<byte>> body,
        int? dataFramePayloadSize,
        CancellationToken cancellationToken)
    {
        await using IAsyncEnumerator<ReadOnlyMemory<byte>> enumerator = body.GetAsyncEnumerator(cancellationToken);
        if (!await enumerator.MoveNextAsync().ConfigureAwait(false))
        {
            byte[] emptyFrame = Http3FrameWriter.WriteData(ReadOnlySpan<byte>.Empty);
            await WriteFinalFrameBytesAsync(stream, emptyFrame, cancellationToken).ConfigureAwait(false);
            EmitFrame(Http3DiagnosticKind.FrameSent, stream.Id, Http3FrameType.Data, 0);
            return;
        }

        ReadOnlyMemory<byte> current = enumerator.Current;
        while (true)
        {
            bool hasNext = await enumerator.MoveNextAsync().ConfigureAwait(false);
            await WriteResponseDataFramesAsync(
                stream,
                current,
                dataFramePayloadSize,
                cancellationToken,
                finalFrame: !hasNext).ConfigureAwait(false);
            if (!hasNext)
            {
                return;
            }

            current = enumerator.Current;
        }
    }

    private async ValueTask WriteResponseDataFramesAsync(
        QuicStream stream,
        ReadOnlyMemory<byte> body,
        int? dataFramePayloadSize,
        CancellationToken cancellationToken,
        bool finalFrame = true)
    {
        if (body.IsEmpty)
        {
            if (finalFrame)
            {
                byte[] emptyFrame = Http3FrameWriter.WriteData(ReadOnlySpan<byte>.Empty);
                await WriteFinalFrameBytesAsync(stream, emptyFrame, cancellationToken).ConfigureAwait(false);
                EmitFrame(Http3DiagnosticKind.FrameSent, stream.Id, Http3FrameType.Data, 0);
            }

            return;
        }

        int framePayloadSize = dataFramePayloadSize ?? ResponseDataFrameChunkSize;
        int offset = 0;
        while (offset < body.Length)
        {
            int count = Math.Min(framePayloadSize, body.Length - offset);
            byte[] dataFrame = Http3FrameWriter.WriteData(body.Span.Slice(offset, count));
            if (finalFrame && offset + count == body.Length)
            {
                await WriteFinalFrameBytesAsync(stream, dataFrame, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                await WriteFrameBytesAsync(stream, dataFrame, cancellationToken).ConfigureAwait(false);
            }

            EmitFrame(Http3DiagnosticKind.FrameSent, stream.Id, Http3FrameType.Data, count);
            offset += count;
        }
    }

    private static async ValueTask WriteFrameBytesAsync(
        QuicStream stream,
        byte[] frameBytes,
        CancellationToken cancellationToken)
    {
        int offset = 0;
        while (offset < frameBytes.Length)
        {
            int count = Math.Min(ResponseWriteChunkSize, frameBytes.Length - offset);
            await stream.WriteAsync(frameBytes, offset, count, cancellationToken).ConfigureAwait(false);
            offset += count;
        }
    }

    private static async ValueTask WriteFinalFrameBytesAsync(
        QuicStream stream,
        byte[] frameBytes,
        CancellationToken cancellationToken)
        => await WriteFinalFrameBytesAsync(stream, frameBytes.AsMemory(), cancellationToken).ConfigureAwait(false);

    private static async ValueTask WriteFinalFrameBytesAsync(
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
                await stream.WriteFinalAsync(frameBytes.Slice(offset, count), cancellationToken).ConfigureAwait(false);
            }
            else
            {
                await stream.WriteAsync(frameBytes.Slice(offset, count), cancellationToken).ConfigureAwait(false);
            }

            offset += count;
        }
    }

    private async ValueTask WriteGoAwayAsync(
        QuicStream controlStream,
        ulong streamId,
        CancellationToken cancellationToken)
    {
        byte[] goAwayFrame = Http3FrameWriter.WriteGoAway(streamId);
        await WriteFrameBytesAsync(controlStream, goAwayFrame, cancellationToken).ConfigureAwait(false);
        EmitFrame(Http3DiagnosticKind.FrameSent, controlStream.Id, Http3FrameType.GoAway, goAwayFrame.Length);
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
        headers[0] = new QPackFieldLine(":status", response.StatusCode.ToString());

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
        if (!IsDiagnosticEnabled(sink))
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
        if (!IsDiagnosticEnabled(sink))
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
        if (!IsDiagnosticEnabled(sink))
        {
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
        if (!IsDiagnosticEnabled(sink))
        {
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
        if (!IsDiagnosticEnabled(sink))
        {
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
        if (!IsDiagnosticEnabled(sink))
        {
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
        if (!IsDiagnosticEnabled(sink))
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

    private static bool IsDiagnosticEnabled(IHttp3DiagnosticsSink? sink)
    {
        return sink?.IsEnabled == true;
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

        public async ValueTask<IReadOnlyList<QPackFieldLine>> DecodeRequestHeadersAsync(
            ulong streamId,
            ReadOnlyMemory<byte> encodedFieldSection,
            CancellationToken cancellationToken)
        {
            Http3Settings settings = await peerSettings.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            TaskCompletionSource<QPackFieldLine[]>? blockedCompletion = null;
            Http3FieldLineBuffer fieldLines = new();
            lock (gate)
            {
                EnsureDecoder(settings);
                QPackFieldSectionDecodeStatus decoded = decoder!.DecodeFieldSection(streamId, encodedFieldSection, fieldLines);
                if (!decoded.IsBlocked)
                {
                    return fieldLines.CommitToReadOnlyList();
                }

                blockedCompletion = new TaskCompletionSource<QPackFieldLine[]>(TaskCreationOptions.RunContinuationsAsynchronously);
                blockedRequests[streamId] = blockedCompletion;
            }

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
    }

    private void EmitFrame(Http3DiagnosticKind kind, long streamId, Http3FrameType frameType, int payloadLength)
    {
        EmitFrameDiagnostic(diagnosticsSink, kind, "server", streamId, frameType, payloadLength);
    }

    private void EmitFrame(Http3DiagnosticKind kind, long streamId, Http3Frame frame)
    {
        if (!IsDiagnosticEnabled(diagnosticsSink))
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
        if (payloadLength == 0 || !IsDiagnosticEnabled(diagnosticsSink))
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
        if (!IsDiagnosticEnabled(diagnosticsSink))
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

}
