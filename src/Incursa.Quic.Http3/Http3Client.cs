// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers;
using System.Net.Security;
using Incursa.Qpack;

namespace Incursa.Quic.Http3;

/// <summary>
/// Minimal HTTP/3 client over the repository QUIC transport.
/// </summary>
public sealed class Http3Client : IAsyncDisposable
{
    private const int RequiredPeerUnidirectionalStreamCount = 3;
    private const int MinimumSuccessfulStatusCode = 200;
    private const int MaximumSuccessfulStatusCode = 299;
    private const ulong ClientInitiatedBidirectionalStreamIdMask = 0x03UL;
    private const ulong ClientInitiatedBidirectionalStreamIdStride = 4;
    private const string MethodConnect = "CONNECT";
    private const string MethodGet = "GET";
    private readonly QuicConnection connection;
    private readonly Http3Settings localSettings;
    private readonly string? userAgent;
    private readonly int readBufferSize;
    private readonly IHttp3DiagnosticsSink? diagnosticsSink;
    private readonly Http3StreamDispatcher peerStreamDispatcher = new(Http3EndpointRole.Client);
    private readonly object peerStreamDispatcherGate = new();
    private readonly ConnectionQPackState qpackState;
    private readonly CancellationTokenSource peerStreamObserverCancellation = new();
    private QuicStream? controlStream;
    private QuicStream? qpackEncoderStream;
    private QuicStream? qpackDecoderStream;
    private Task? peerStreamObserverTask;
    private ulong nextClientRequestStreamId;
    private ulong? peerGoAwayStreamId;
    private int disposed;

    private Http3Client(QuicConnection connection, Http3ClientOptions options)
    {
        this.connection = connection ?? throw new ArgumentNullException(nameof(connection));
        ArgumentNullException.ThrowIfNull(options);
        localSettings = options.Settings ?? throw new ArgumentException("HTTP/3 client settings must not be null.", nameof(options));
        userAgent = options.UserAgent;
        readBufferSize = options.ReadBufferSize > 0
            ? options.ReadBufferSize
            : throw new ArgumentOutOfRangeException(nameof(options), "The HTTP/3 read buffer size must be positive.");
        diagnosticsSink = options.DiagnosticsSink;
        qpackState = new ConnectionQPackState(localSettings);
        Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.ConnectionStarted)
        {
            Role = "client",
        });
    }

    /// <summary>
    /// Opens a QUIC connection with ALPN h3 and writes the required HTTP/3 unidirectional streams.
    /// </summary>
    public static async ValueTask<Http3Client> ConnectAsync(
        QuicClientConnectionOptions quicOptions,
        Http3ClientOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(quicOptions);
        EnsureHttp3Alpn(quicOptions);
        EnsureHttp3TransportLimits(quicOptions);

        Http3Client client = new(
            await QuicConnection.ConnectAsync(quicOptions, cancellationToken).ConfigureAwait(false),
            options ?? new Http3ClientOptions());

        try
        {
            await client.OpenRequiredUnidirectionalStreamsAsync(cancellationToken).ConfigureAwait(false);
            return client;
        }
        catch
        {
            await client.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>
    /// Attaches the minimal HTTP/3 client layer to an already established QUIC connection and writes the required unidirectional streams.
    /// </summary>
    public static async ValueTask<Http3Client> AttachAsync(
        QuicConnection connection,
        Http3ClientOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(connection);
        Http3Client client = new(connection, options ?? new Http3ClientOptions());
        try
        {
            await client.OpenRequiredUnidirectionalStreamsAsync(cancellationToken).ConfigureAwait(false);
            return client;
        }
        catch
        {
            await client.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>
    /// Opens a temporary client connection, sends a GET request, reads one response, and closes the client.
    /// </summary>
    public static async ValueTask<Http3Response> GetAsync(
        QuicClientConnectionOptions quicOptions,
        Uri requestUri,
        Http3ClientOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        await using Http3Client client = await ConnectAsync(quicOptions, options, cancellationToken).ConfigureAwait(false);
        return await client.GetAsync(requestUri, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Sends a GET request and reads a complete response from a client-initiated bidirectional stream.
    /// </summary>
    public async ValueTask<Http3Response> GetAsync(Uri requestUri, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        ArgumentNullException.ThrowIfNull(requestUri);
        if (!requestUri.IsAbsoluteUri)
        {
            throw new ArgumentException("The HTTP/3 request URI must be absolute.", nameof(requestUri));
        }

        ThrowIfPeerGoAwayRejectsNextRequest();

        long requestStartedTimestamp = 0;
        bool requestStarted = false;
        try
        {
            requestStartedTimestamp = Http3Metrics.GetTimestamp();
            requestStarted = true;
            Http3Metrics.RecordRequestStarted("client");
            Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.RequestStarted)
            {
                Role = "client",
                Method = MethodGet,
                Path = BuildPath(requestUri),
            });

            await using QuicStream requestStream = await connection
                .OpenOutboundStreamAsync(QuicStreamType.Bidirectional, cancellationToken)
                .ConfigureAwait(false);
            RecordOpenedClientRequestStream(checked((ulong)requestStream.Id));

            Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.StreamOpened)
            {
                Role = "client",
                StreamId = requestStream.Id,
                StreamKind = Http3StreamKind.Request,
            });

            byte[] requestHeaders = QPackEncoder.EncodeFieldSection(BuildGetRequestHeaders(requestUri));
            byte[] headersFrame = Http3FrameWriter.WriteHeaders(requestHeaders);
            await requestStream.WriteAsync(headersFrame, 0, headersFrame.Length, cancellationToken).ConfigureAwait(false);
            EmitFrame(Http3DiagnosticKind.FrameSent, requestStream.Id, Http3FrameType.Headers, requestHeaders.Length);
            await requestStream.CompleteWritesAsync(cancellationToken).ConfigureAwait(false);

            Http3Response response = await ReadResponseAsync(requestStream, cancellationToken).ConfigureAwait(false);
            Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.RequestCompleted)
            {
                Role = "client",
                StreamId = requestStream.Id,
                Method = MethodGet,
                Path = BuildPath(requestUri),
                StatusCode = response.StatusCode,
                PayloadLength = response.Body.Length,
            });
            Http3Metrics.RecordRequestCompleted("client", response.StatusCode, requestStartedTimestamp);
            Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.StreamClosed)
            {
                Role = "client",
                StreamId = requestStream.Id,
                StreamKind = Http3StreamKind.Request,
            });
            return response;
        }
        catch (Exception ex)
        {
            if (requestStarted)
            {
                Http3Metrics.RecordRequestFailed("client", Http3Metrics.NormalizeFailureReason(ex), requestStartedTimestamp);
            }

            EmitError(ex);
            throw;
        }
    }

    /// <summary>
    /// Opens an RFC 9220 WebSocket Extended CONNECT tunnel without ending the request stream.
    /// </summary>
    public async ValueTask<Http3WebSocketClientTunnelContext> OpenWebSocketAsync(
        Uri requestUri,
        CancellationToken cancellationToken = default)
    {
        return await OpenWebSocketAsync(requestUri, additionalHeaders: null, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Opens an RFC 9220 WebSocket Extended CONNECT tunnel with additional non-pseudo request headers.
    /// </summary>
    public async ValueTask<Http3WebSocketClientTunnelContext> OpenWebSocketAsync(
        Uri requestUri,
        IEnumerable<QPackFieldLine>? additionalHeaders,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        ArgumentNullException.ThrowIfNull(requestUri);
        if (!requestUri.IsAbsoluteUri)
        {
            throw new ArgumentException("The HTTP/3 WebSocket request URI must be absolute.", nameof(requestUri));
        }

        if (localSettings.EnableConnectProtocol != 1)
        {
            throw new Http3Exception(
                Http3ErrorCode.SettingsError,
                "HTTP/3 WebSocket Extended CONNECT requires local SETTINGS_ENABLE_CONNECT_PROTOCOL to be 1 before opening the tunnel.");
        }

        ThrowIfPeerGoAwayRejectsNextRequest();

        long requestStartedTimestamp = 0;
        bool requestStarted = false;
        QuicStream? requestStream = null;
        try
        {
            requestStartedTimestamp = Http3Metrics.GetTimestamp();
            requestStarted = true;
            Http3Metrics.RecordRequestStarted("client");
            Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.RequestStarted)
            {
                Role = "client",
                Method = MethodConnect,
                Path = BuildPath(requestUri),
            });

            requestStream = await connection
                .OpenOutboundStreamAsync(QuicStreamType.Bidirectional, cancellationToken)
                .ConfigureAwait(false);
            RecordOpenedClientRequestStream(checked((ulong)requestStream.Id));

            Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.StreamOpened)
            {
                Role = "client",
                StreamId = requestStream.Id,
                StreamKind = Http3StreamKind.Request,
            });

            byte[] requestHeaders = QPackEncoder.EncodeFieldSection(
                BuildWebSocketConnectRequestHeaders(requestUri, additionalHeaders));
            byte[] headersFrame = Http3FrameWriter.WriteHeaders(requestHeaders);
            await requestStream.WriteAsync(headersFrame, 0, headersFrame.Length, cancellationToken).ConfigureAwait(false);
            EmitFrame(Http3DiagnosticKind.FrameSent, requestStream.Id, Http3FrameType.Headers, requestHeaders.Length);

            Http3WebSocketClientTunnelContext tunnel = await ReadWebSocketConnectResponseAsync(
                requestStream,
                cancellationToken).ConfigureAwait(false);
            requestStream = null;

            Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.RequestCompleted)
            {
                Role = "client",
                StreamId = tunnel.Stream.Id,
                Method = MethodConnect,
                Path = BuildPath(requestUri),
                StatusCode = tunnel.StatusCode,
            });
            Http3Metrics.RecordRequestCompleted("client", tunnel.StatusCode, requestStartedTimestamp);
            return tunnel;
        }
        catch (Exception ex)
        {
            if (requestStarted)
            {
                Http3Metrics.RecordRequestFailed("client", Http3Metrics.NormalizeFailureReason(ex), requestStartedTimestamp);
            }

            if (requestStream is not null)
            {
                await requestStream.DisposeAsync().ConfigureAwait(false);
            }

            EmitError(ex);
            throw;
        }
    }

    /// <summary>
    /// Disposes the client streams and underlying QUIC connection.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
        {
            return;
        }

        await peerStreamObserverCancellation.CancelAsync().ConfigureAwait(false);
        if (peerStreamObserverTask is not null)
        {
            try
            {
                await peerStreamObserverTask.ConfigureAwait(false);
            }
            catch (OperationCanceledException exception)
            {
                SuppressExpectedException(exception);
            }
        }

        if (qpackDecoderStream is not null)
        {
            await qpackDecoderStream.DisposeAsync().ConfigureAwait(false);
        }

        if (qpackEncoderStream is not null)
        {
            await qpackEncoderStream.DisposeAsync().ConfigureAwait(false);
        }

        if (controlStream is not null)
        {
            await controlStream.DisposeAsync().ConfigureAwait(false);
        }

        Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.ConnectionClosed)
        {
            Role = "client",
        });
        await connection.DisposeAsync().ConfigureAwait(false);
        peerStreamObserverCancellation.Dispose();
    }

    private static void EnsureHttp3Alpn(QuicClientConnectionOptions quicOptions)
    {
        SslClientAuthenticationOptions authenticationOptions = quicOptions.ClientAuthenticationOptions
            ?? throw new ArgumentException("QUIC client authentication options are required.", nameof(quicOptions));

        authenticationOptions.ApplicationProtocols ??= [];
        if (authenticationOptions.ApplicationProtocols.Count == 0)
        {
            authenticationOptions.ApplicationProtocols.Add(SslApplicationProtocol.Http3);
            return;
        }

        foreach (SslApplicationProtocol protocol in authenticationOptions.ApplicationProtocols)
        {
            if (protocol.Equals(SslApplicationProtocol.Http3))
            {
                return;
            }
        }

        throw new ArgumentException("HTTP/3 requires ALPN h3 in the QUIC client authentication options.", nameof(quicOptions));
    }

    private static void EnsureHttp3TransportLimits(QuicClientConnectionOptions quicOptions)
    {
        if (quicOptions.MaxInboundUnidirectionalStreams < RequiredPeerUnidirectionalStreamCount)
        {
            quicOptions.MaxInboundUnidirectionalStreams = RequiredPeerUnidirectionalStreamCount;
        }
    }

    private async ValueTask OpenRequiredUnidirectionalStreamsAsync(CancellationToken cancellationToken)
    {
        controlStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Unidirectional, cancellationToken).ConfigureAwait(false);
        byte[] initialControlStream = Http3SettingsWriter.WriteInitialControlStream(localSettings);
        await controlStream.WriteAsync(initialControlStream, 0, initialControlStream.Length, cancellationToken).ConfigureAwait(false);
        Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.StreamOpened)
        {
            Role = "client",
            StreamId = controlStream.Id,
            StreamKind = Http3StreamKind.Control,
        });
        EmitFrame(Http3DiagnosticKind.FrameSent, controlStream.Id, Http3FrameType.Settings, initialControlStream.Length);
        Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.SettingsSent)
        {
            Role = "client",
            StreamId = controlStream.Id,
        });

        qpackEncoderStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Unidirectional, cancellationToken).ConfigureAwait(false);
        await WriteStreamTypeAsync(qpackEncoderStream, Http3StreamType.QPackEncoder, cancellationToken).ConfigureAwait(false);
        Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.StreamOpened)
        {
            Role = "client",
            StreamId = qpackEncoderStream.Id,
            StreamKind = Http3StreamKind.QPackEncoder,
        });
        Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.QPackInstructionSent)
        {
            Role = "client",
            StreamId = qpackEncoderStream.Id,
            StreamKind = Http3StreamKind.QPackEncoder,
            QPackInstruction = "stream_type",
        });

        qpackDecoderStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Unidirectional, cancellationToken).ConfigureAwait(false);
        await WriteStreamTypeAsync(qpackDecoderStream, Http3StreamType.QPackDecoder, cancellationToken).ConfigureAwait(false);
        Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.StreamOpened)
        {
            Role = "client",
            StreamId = qpackDecoderStream.Id,
            StreamKind = Http3StreamKind.QPackDecoder,
        });
        Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.QPackInstructionSent)
        {
            Role = "client",
            StreamId = qpackDecoderStream.Id,
            StreamKind = Http3StreamKind.QPackDecoder,
            QPackInstruction = "stream_type",
        });

        StartPeerUnidirectionalStreamObserver();
    }

    private void StartPeerUnidirectionalStreamObserver()
    {
        if (peerStreamObserverTask is not null)
        {
            return;
        }

        peerStreamObserverTask = Task.Run(
            () => ObservePeerUnidirectionalStreamsAsync(peerStreamObserverCancellation.Token));
    }

    private async Task ObservePeerUnidirectionalStreamsAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            QuicStream? stream;
            try
            {
                stream = await connection.TryAcceptInboundStreamAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException exception) when (cancellationToken.IsCancellationRequested)
            {
                SuppressExpectedException(exception);
                break;
            }
            catch (ObjectDisposedException exception) when (Volatile.Read(ref disposed) != 0)
            {
                SuppressExpectedException(exception);
                break;
            }
            catch (QuicException exception)
            {
                SuppressExpectedException(exception);
                break;
            }

            if (stream is null)
            {
                break;
            }

            if (stream.Type != QuicStreamType.Unidirectional)
            {
                _ = RejectPeerBidirectionalStreamAsync(stream);
                continue;
            }

            _ = ObservePeerUnidirectionalStreamAsync(stream, cancellationToken);
        }
    }

    private async Task RejectPeerBidirectionalStreamAsync(QuicStream stream)
    {
        await using (stream.ConfigureAwait(false))
        {
            try
            {
                lock (peerStreamDispatcherGate)
                {
                    peerStreamDispatcher.RegisterBidirectionalStreamState(checked((ulong)stream.Id));
                }
            }
            catch (Http3Exception exception)
            {
                EmitError(exception);
            }
        }
    }

    private async Task ObservePeerUnidirectionalStreamAsync(
        QuicStream stream,
        CancellationToken cancellationToken)
    {
        await using (stream.ConfigureAwait(false))
        {
            byte[] buffer = QuicBufferPool.RentBytes(readBufferSize);
            byte[] pendingStreamType = [];
            Http3StreamKind streamKind = Http3StreamKind.Unknown;
            try
            {
                lock (peerStreamDispatcherGate)
                {
                    peerStreamDispatcher.RegisterUnidirectionalStreamState(checked((ulong)stream.Id));
                }

                while (true)
                {
                    int bytesRead = await stream.TryReadTerminalAsync(buffer.AsMemory(0, buffer.Length), cancellationToken).ConfigureAwait(false);
                    if (bytesRead == 0)
                    {
                        lock (peerStreamDispatcherGate)
                        {
                            peerStreamDispatcher.ReceiveUnidirectionalStreamTypeBytes(
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
                    lock (peerStreamDispatcherGate)
                    {
                        streamInfo = peerStreamDispatcher.ReceiveUnidirectionalStreamTypeBytes(
                            checked((ulong)stream.Id),
                            streamTypeBytes);
                    }

                    streamKind = streamInfo.Kind;
                    Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.StreamOpened)
                    {
                        Role = "client",
                        StreamId = stream.Id,
                        StreamKind = streamKind,
                    });

                    await ObservePeerUnidirectionalPayloadAsync(
                        stream,
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
            catch (ObjectDisposedException exception) when (Volatile.Read(ref disposed) != 0)
            {
                SuppressExpectedException(exception);
            }
            catch (QuicException exception)
            {
                SuppressExpectedException(exception);
            }
            catch (Http3Exception exception)
            {
                EmitError(exception);
            }
            finally
            {
                Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.StreamClosed)
                {
                    Role = "client",
                    StreamId = stream.Id,
                    StreamKind = streamKind,
                });
                QuicBufferPool.ReturnBytes(buffer);
            }
        }
    }

    private async ValueTask ObservePeerUnidirectionalPayloadAsync(
        QuicStream stream,
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
                    initialPayload,
                    buffer,
                    cancellationToken).ConfigureAwait(false);
                break;
            case Http3StreamKind.QPackEncoder:
            case Http3StreamKind.QPackDecoder:
                await DrainPeerQPackStreamAsync(stream, streamKind, initialPayload, buffer, cancellationToken).ConfigureAwait(false);
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
        byte[] initialPayload,
        byte[] buffer,
        CancellationToken cancellationToken)
    {
        Http3FrameReader frameReader = new();
        ProcessPeerControlBytes(frameReader, initialPayload, stream.Id);

        while (true)
        {
            int bytesRead = await stream.TryReadTerminalAsync(buffer.AsMemory(0, buffer.Length), cancellationToken).ConfigureAwait(false);
            if (bytesRead == 0)
            {
                ProcessPeerControlFrames(frameReader.Complete(), stream.Id);
                return;
            }

            ProcessPeerControlBytes(frameReader, buffer.AsSpan(0, bytesRead), stream.Id);
        }
    }

    private async ValueTask DrainPeerQPackStreamAsync(
        QuicStream stream,
        Http3StreamKind streamKind,
        byte[] initialPayload,
        byte[] buffer,
        CancellationToken cancellationToken)
    {
        EmitQPackBytesReceived(stream.Id, streamKind, initialPayload.Length);
        if (streamKind == Http3StreamKind.QPackEncoder)
        {
            qpackState.ProcessPeerEncoderStreamBytes(initialPayload);
        }

        while (true)
        {
            int bytesRead = await stream.TryReadTerminalAsync(buffer.AsMemory(0, buffer.Length), cancellationToken).ConfigureAwait(false);
            if (bytesRead == 0)
            {
                return;
            }

            EmitQPackBytesReceived(stream.Id, streamKind, bytesRead);
            if (streamKind == Http3StreamKind.QPackEncoder)
            {
                qpackState.ProcessPeerEncoderStreamBytes(buffer.AsSpan(0, bytesRead));
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

    private void ProcessPeerControlBytes(
        Http3FrameReader frameReader,
        ReadOnlySpan<byte> bytes,
        long streamId)
    {
        if (bytes.IsEmpty)
        {
            return;
        }

        ProcessPeerControlFrames(frameReader.Read(bytes), streamId);
    }

    private void ProcessPeerControlFrames(
        IEnumerable<Http3Frame> frames,
        long streamId)
    {
        foreach (Http3Frame frame in frames)
        {
            lock (peerStreamDispatcherGate)
            {
                peerStreamDispatcher.ReceiveFrame(checked((ulong)streamId), frame);
            }

            EmitFrame(Http3DiagnosticKind.FrameReceived, streamId, frame);
            switch (frame)
            {
                case Http3SettingsFrame:
                    Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.SettingsReceived)
                    {
                        Role = "client",
                        StreamId = streamId,
                    });
                    break;
                case Http3GoAwayFrame goAwayFrame:
                    RecordPeerGoAway(goAwayFrame.StreamOrPushId);
                    break;
            }
        }
    }

    private void EmitQPackBytesReceived(long streamId, Http3StreamKind streamKind, int payloadLength)
    {
        if (payloadLength == 0)
        {
            return;
        }

        Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.QPackInstructionReceived)
        {
            Role = "client",
            StreamId = streamId,
            StreamKind = streamKind,
            PayloadLength = payloadLength,
            QPackInstruction = "bytes",
        });
    }

    private IReadOnlyList<QPackFieldLine> BuildGetRequestHeaders(Uri requestUri)
    {
        List<QPackFieldLine> headers =
        [
            new(":method", MethodGet),
            new(":scheme", requestUri.Scheme),
            new(":authority", BuildAuthority(requestUri)),
            new(":path", BuildPath(requestUri)),
        ];

        if (!string.IsNullOrWhiteSpace(userAgent))
        {
            headers.Add(new QPackFieldLine("user-agent", userAgent));
        }

        return headers;
    }

    private IReadOnlyList<QPackFieldLine> BuildWebSocketConnectRequestHeaders(
        Uri requestUri,
        IEnumerable<QPackFieldLine>? additionalHeaders)
    {
        List<QPackFieldLine> headers =
        [
            new(":method", MethodConnect),
            new(":protocol", Http3ExtendedConnect.WebSocketProtocol),
            new(":scheme", requestUri.Scheme),
            new(":authority", BuildAuthority(requestUri)),
            new(":path", BuildPath(requestUri)),
        ];

        if (!string.IsNullOrWhiteSpace(userAgent))
        {
            headers.Add(new QPackFieldLine("user-agent", userAgent));
        }

        if (additionalHeaders is not null)
        {
            foreach (QPackFieldLine header in additionalHeaders)
            {
                if (header.Name.StartsWith(':'))
                {
                    throw new ArgumentException("Additional HTTP/3 WebSocket request headers cannot include pseudo-fields.", nameof(additionalHeaders));
                }

                headers.Add(header);
            }
        }

        return headers;
    }

    private async ValueTask<Http3WebSocketClientTunnelContext> ReadWebSocketConnectResponseAsync(
        QuicStream requestStream,
        CancellationToken cancellationToken)
    {
        Http3FrameReader frameReader = new();
        Http3ResponseSequenceValidator validator = new();
        byte[] buffer = new byte[1];

        while (true)
        {
            int bytesRead = await requestStream.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false);
            if (bytesRead == 0)
            {
                foreach (Http3Frame frame in frameReader.Complete())
                {
                    await ProcessWebSocketConnectResponseFrameAsync(
                        frame,
                        validator,
                        requestStream.Id,
                        cancellationToken).ConfigureAwait(false);
                    if (validator.FinalResponseSeen)
                    {
                        return CreateWebSocketTunnelOrThrow(requestStream, validator);
                    }
                }

                throw new Http3Exception(Http3ErrorCode.MessageError, "The HTTP/3 WebSocket Extended CONNECT response ended before final response headers.");
            }

            foreach (Http3Frame frame in frameReader.Read(buffer.AsSpan(0, bytesRead)))
            {
                await ProcessWebSocketConnectResponseFrameAsync(
                    frame,
                    validator,
                    requestStream.Id,
                    cancellationToken).ConfigureAwait(false);
                if (validator.FinalResponseSeen)
                {
                    return CreateWebSocketTunnelOrThrow(requestStream, validator);
                }
            }
        }
    }

    private Http3WebSocketClientTunnelContext CreateWebSocketTunnelOrThrow(
        QuicStream requestStream,
        Http3ResponseSequenceValidator validator)
    {
        IReadOnlyList<QPackFieldLine> headers = validator.FinalResponseHeaders
            ?? throw new Http3Exception(Http3ErrorCode.MessageError, "The HTTP/3 WebSocket Extended CONNECT response did not contain final response headers.");
        int statusCode = validator.FinalStatusCode!.Value;
        if (statusCode is < MinimumSuccessfulStatusCode or > MaximumSuccessfulStatusCode)
        {
            throw new Http3Exception(
                Http3ErrorCode.RequestRejected,
                "The HTTP/3 WebSocket Extended CONNECT response was not successful.");
        }

        Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.ResponseStarted)
        {
            Role = "client",
            StreamId = requestStream.Id,
        });
        return new Http3WebSocketClientTunnelContext(requestStream, statusCode, headers, readBufferSize);
    }

    private async ValueTask ProcessWebSocketConnectResponseFrameAsync(
        Http3Frame frame,
        Http3ResponseSequenceValidator validator,
        long streamId,
        CancellationToken cancellationToken)
    {
        EmitFrame(Http3DiagnosticKind.FrameReceived, streamId, frame);
        switch (frame)
        {
            case Http3HeadersFrame headersFrame:
                IReadOnlyList<QPackFieldLine> fieldSection = await qpackState.DecodeResponseHeadersAsync(
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
                throw new Http3Exception(Http3ErrorCode.FrameUnexpected, "The HTTP/3 response stream contained an invalid frame type.");
        }
    }

    private async ValueTask<Http3Response> ReadResponseAsync(QuicStream requestStream, CancellationToken cancellationToken)
    {
        Http3FrameReader frameReader = new();
        Http3ResponseSequenceValidator validator = new();
        byte[] buffer = new byte[readBufferSize];
        ArrayBufferWriter<byte> body = new();
        bool streamCompleted = false;

        while (true)
        {
            int bytesRead = await requestStream.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false);
            if (bytesRead == 0)
            {
                streamCompleted = true;
                foreach (Http3Frame frame in frameReader.Complete())
                {
                    await ProcessResponseFrameAsync(frame, validator, body, requestStream.Id, cancellationToken).ConfigureAwait(false);
                }

                break;
            }

            foreach (Http3Frame frame in frameReader.Read(buffer.AsSpan(0, bytesRead)))
            {
                await ProcessResponseFrameAsync(frame, validator, body, requestStream.Id, cancellationToken).ConfigureAwait(false);
            }

            ValidateContentLengthNotExceeded(validator, body.WrittenCount);
        }

        IReadOnlyList<QPackFieldLine>? headers = validator.FinalResponseHeaders;
        if (headers is null)
        {
            throw new Http3Exception(Http3ErrorCode.MessageError, "The HTTP/3 response did not contain a HEADERS frame.");
        }

        if (streamCompleted)
        {
            validator.Complete();
        }
        else
        {
            Http3HeaderValidator.ValidateResponseHeaders(headers, checked((ulong)body.WrittenCount));
        }

        int statusCode = validator.FinalStatusCode!.Value;
        byte[] bodyBytes = body.WrittenSpan.ToArray();
        Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.ResponseCompleted)
        {
            Role = "client",
            StreamId = requestStream.Id,
            StatusCode = statusCode,
            PayloadLength = bodyBytes.Length,
        });
        return new Http3Response(statusCode, headers, bodyBytes, streamCompleted);
    }

    private static void ValidateContentLengthNotExceeded(
        Http3ResponseSequenceValidator validator,
        int receivedBodyLength)
    {
        IReadOnlyList<QPackFieldLine>? headers = validator.FinalResponseHeaders;
        if (headers is null)
        {
            return;
        }

        if (!TryGetContentLength(headers, out ulong contentLength))
        {
            return;
        }

        ulong receivedLength = checked((ulong)receivedBodyLength);
        if (receivedLength > contentLength)
        {
            throw new Http3Exception(Http3ErrorCode.MessageError, "The HTTP/3 response body exceeded Content-Length.");
        }
    }

    private static bool TryGetContentLength(IReadOnlyList<QPackFieldLine> headers, out ulong contentLength)
    {
        foreach (QPackFieldLine header in headers)
        {
            if (StringComparer.Ordinal.Equals(header.Name, "content-length"))
            {
                return ulong.TryParse(header.Value, out contentLength);
            }
        }

        contentLength = 0;
        return false;
    }

    private async ValueTask ProcessResponseFrameAsync(
        Http3Frame frame,
        Http3ResponseSequenceValidator validator,
        IBufferWriter<byte> body,
        long streamId,
        CancellationToken cancellationToken)
    {
        EmitFrame(Http3DiagnosticKind.FrameReceived, streamId, frame);
        switch (frame)
        {
            case Http3HeadersFrame headersFrame:
                Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.ResponseStarted)
                {
                    Role = "client",
                    StreamId = streamId,
                });
                IReadOnlyList<QPackFieldLine> fieldSection = await qpackState.DecodeResponseHeadersAsync(
                        checked((ulong)streamId),
                        headersFrame.EncodedFieldSection,
                        cancellationToken).ConfigureAwait(false);
                validator.ReceiveOwnedHeaders(fieldSection);
                break;
            case Http3DataFrame dataFrame:
                validator.ReceiveData(checked((ulong)dataFrame.Data.Length));
                body.Write(dataFrame.Data.Span);
                break;
            case Http3UnknownFrame:
                break;
            default:
                throw new Http3Exception(Http3ErrorCode.FrameUnexpected, "The HTTP/3 response stream contained an invalid frame type.");
        }
    }

    private sealed class ConnectionQPackState
    {
        private readonly object gate = new();
        private readonly Dictionary<ulong, TaskCompletionSource<QPackFieldLine[]>> blockedResponses = [];
        private readonly QPackDecoder decoder;

        public ConnectionQPackState(Http3Settings localSettings)
        {
            ArgumentNullException.ThrowIfNull(localSettings);

            decoder = new QPackDecoder(
                checked((int)localSettings.QPackMaxTableCapacity),
                checked((int)localSettings.QPackBlockedStreams));
        }

        public ValueTask<IReadOnlyList<QPackFieldLine>> DecodeResponseHeadersAsync(
            ulong streamId,
            ReadOnlyMemory<byte> encodedFieldSection,
            CancellationToken cancellationToken)
        {
            TaskCompletionSource<QPackFieldLine[]>? blockedCompletion = null;
            Http3FieldLineBuffer fieldLines = new();
            lock (gate)
            {
                QPackFieldSectionDecodeStatus decoded = decoder.DecodeFieldSection(streamId, encodedFieldSection, fieldLines);
                if (!decoded.IsBlocked)
                {
                    return new ValueTask<IReadOnlyList<QPackFieldLine>>(fieldLines.CommitToReadOnlyList());
                }

                blockedCompletion = new TaskCompletionSource<QPackFieldLine[]>(TaskCreationOptions.RunContinuationsAsynchronously);
                blockedResponses[streamId] = blockedCompletion;
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
                CompleteUnblockedResponses(decoder.DecodeEncoderStream(bytes));
            }
        }

        private void CompleteUnblockedResponses(QPackFieldSectionDecodeResult[] results)
        {
            foreach (QPackFieldSectionDecodeResult result in results)
            {
                if (blockedResponses.Remove(result.StreamId, out TaskCompletionSource<QPackFieldLine[]>? completion))
                {
                    completion.TrySetResult(result.FieldLines);
                }
            }
        }
    }

    private void EmitFrame(Http3DiagnosticKind kind, long streamId, Http3FrameType frameType, int payloadLength)
    {
        Emit(new Http3DiagnosticEvent(kind)
        {
            Role = "client",
            StreamId = streamId,
            FrameType = frameType,
            RawFrameType = checked((ulong)frameType),
            PayloadLength = payloadLength,
        });
    }

    private void EmitFrame(Http3DiagnosticKind kind, long streamId, Http3Frame frame)
    {
        Emit(new Http3DiagnosticEvent(kind)
        {
            Role = "client",
            StreamId = streamId,
            FrameType = Enum.IsDefined(typeof(Http3FrameType), (long)frame.Type) ? (Http3FrameType)frame.Type : null,
            RawFrameType = frame.Type,
            PayloadLength = frame.Payload.Length,
        });
    }

    private void EmitError(Exception exception)
    {
        Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.Error)
        {
            Role = "client",
            ErrorCode = exception is Http3Exception http3Exception
                ? http3Exception.ErrorCode.ToString()
                : exception.GetType().Name,
            Message = exception.Message,
        });
    }

    private void Emit(Http3DiagnosticEvent diagnosticEvent)
    {
        if (diagnosticsSink?.IsEnabled != true)
        {
            return;
        }

        diagnosticsSink.Emit(diagnosticEvent);
    }

    private void ThrowIfPeerGoAwayRejectsNextRequest()
    {
        lock (peerStreamDispatcherGate)
        {
            if (peerGoAwayStreamId.HasValue && nextClientRequestStreamId >= peerGoAwayStreamId.Value)
            {
                throw new Http3Exception(Http3ErrorCode.RequestRejected, "The HTTP/3 peer has sent GOAWAY for new request streams.");
            }
        }
    }

    private void RecordOpenedClientRequestStream(ulong streamId)
    {
        lock (peerStreamDispatcherGate)
        {
            ulong nextStreamId = checked(streamId + ClientInitiatedBidirectionalStreamIdStride);
            if (nextStreamId > nextClientRequestStreamId)
            {
                nextClientRequestStreamId = nextStreamId;
            }
        }
    }

    private void RecordPeerGoAway(ulong streamOrPushId)
    {
        if ((streamOrPushId & ClientInitiatedBidirectionalStreamIdMask) != 0)
        {
            throw new Http3Exception(Http3ErrorCode.IdError, "The HTTP/3 server GOAWAY frame carried an invalid client request stream ID.");
        }

        lock (peerStreamDispatcherGate)
        {
            peerGoAwayStreamId = peerGoAwayStreamId.HasValue
                ? Math.Min(peerGoAwayStreamId.Value, streamOrPushId)
                : streamOrPushId;
        }
    }

    private static string BuildAuthority(Uri requestUri)
    {
        if (requestUri.IsDefaultPort)
        {
            return requestUri.IdnHost;
        }

        return string.Create(
            requestUri.IdnHost.Length + 1 + requestUri.Port.ToString().Length,
            requestUri,
            static (destination, uri) =>
            {
                uri.IdnHost.AsSpan().CopyTo(destination);
                destination[uri.IdnHost.Length] = ':';
                uri.Port.TryFormat(destination[(uri.IdnHost.Length + 1)..], out _);
            });
    }

    private static string BuildPath(Uri requestUri)
    {
        string path = string.IsNullOrEmpty(requestUri.AbsolutePath) ? "/" : requestUri.AbsolutePath;
        return string.IsNullOrEmpty(requestUri.Query) ? path : path + requestUri.Query;
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

    private static void SuppressExpectedException(Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);
    }
}
