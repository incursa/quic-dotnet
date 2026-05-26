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
    private const int ResponseWriteChunkSize = 1024;
    private const int ResponseDataFrameChunkSize = 16 * 1024;
    private const int FieldSectionRequiredInsertCountPrefixBits = 8;
    private const int FieldSectionBasePrefixBits = 7;
    private const int IndexedFieldPrefixBits = 6;
    private const byte StaticIndexedFieldPrefix = 0xC0;
    private const int StaticNameReferencePrefixBits = 4;
    private const byte LiteralWithStaticNameReferencePrefix = 0x50;
    private const int LiteralNamePrefixBits = 4;
    private const byte LiteralWithLiteralNamePrefix = 0x20;
    private const int StringLiteralPrefixBits = 8;
    private const int StatusStaticNameIndex = 24;
    private static readonly Encoding HeaderTextEncoding = Encoding.Latin1;

    private readonly QuicListener listener;
    private readonly IHttp3RequestHandler handler;
    private readonly Http3Settings localSettings;
    private readonly int readBufferSize;
    private readonly IHttp3DiagnosticsSink? diagnosticsSink;
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
                Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.ConnectionStarted)
                {
                    Role = "server",
                });
                QuicStream controlStream = await OpenRequiredUnidirectionalStreamsAsync(connection, cancellationToken).ConfigureAwait(false);
                await AcceptStreamsAsync(connection, controlStream, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException exception) when (cancellationToken.IsCancellationRequested)
            {
                SuppressExpectedException(exception);
            }
            catch (ObjectDisposedException exception) when (Volatile.Read(ref disposed) != 0)
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
                Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.ConnectionClosed)
                {
                    Role = "server",
                });
            }
        }
    }

    private async ValueTask<QuicStream> OpenRequiredUnidirectionalStreamsAsync(QuicConnection connection, CancellationToken cancellationToken)
    {
        QuicStream controlStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Unidirectional, cancellationToken).ConfigureAwait(false);
        byte[] initialControlStream = Http3SettingsWriter.WriteInitialControlStream(localSettings);
        await controlStream.WriteAsync(initialControlStream, 0, initialControlStream.Length, cancellationToken).ConfigureAwait(false);
        Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.StreamOpened)
        {
            Role = "server",
            StreamId = controlStream.Id,
            StreamKind = Http3StreamKind.Control,
        });
        EmitFrame(Http3DiagnosticKind.FrameSent, controlStream.Id, Http3FrameType.Settings, initialControlStream.Length);
        Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.SettingsSent)
        {
            Role = "server",
            StreamId = controlStream.Id,
        });

        QuicStream qpackEncoderStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Unidirectional, cancellationToken).ConfigureAwait(false);
        await WriteStreamTypeAsync(qpackEncoderStream, Http3StreamType.QPackEncoder, cancellationToken).ConfigureAwait(false);
        Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.StreamOpened)
        {
            Role = "server",
            StreamId = qpackEncoderStream.Id,
            StreamKind = Http3StreamKind.QPackEncoder,
        });
        Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.QPackInstructionSent)
        {
            Role = "server",
            StreamId = qpackEncoderStream.Id,
            StreamKind = Http3StreamKind.QPackEncoder,
            QPackInstruction = "stream_type",
        });

        QuicStream qpackDecoderStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Unidirectional, cancellationToken).ConfigureAwait(false);
        await WriteStreamTypeAsync(qpackDecoderStream, Http3StreamType.QPackDecoder, cancellationToken).ConfigureAwait(false);
        Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.StreamOpened)
        {
            Role = "server",
            StreamId = qpackDecoderStream.Id,
            StreamKind = Http3StreamKind.QPackDecoder,
        });
        Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.QPackInstructionSent)
        {
            Role = "server",
            StreamId = qpackDecoderStream.Id,
            StreamKind = Http3StreamKind.QPackDecoder,
            QPackInstruction = "stream_type",
        });

        return controlStream;
    }

    private async Task AcceptStreamsAsync(QuicConnection connection, QuicStream controlStream, CancellationToken cancellationToken)
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

            Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.StreamOpened)
            {
                Role = "server",
                StreamId = stream.Id,
                StreamKind = streamKind,
            });
            _ = stream.Type == QuicStreamType.Bidirectional
                ? HandleRequestStreamAsync(connection, stream, controlStream, cancellationToken)
                : ObservePeerUnidirectionalStreamAsync(stream, dispatcher, dispatcherGate, cancellationToken);
        }
    }

    private async Task ObservePeerUnidirectionalStreamAsync(
        QuicStream stream,
        Http3StreamDispatcher dispatcher,
        object dispatcherGate,
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
                    Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.StreamOpened)
                    {
                        Role = "server",
                        StreamId = stream.Id,
                        StreamKind = streamKind,
                    });

                    await ObservePeerUnidirectionalPayloadAsync(
                        stream,
                        dispatcher,
                        dispatcherGate,
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
            catch (Http3Exception exception)
            {
                EmitError(exception);
            }
            finally
            {
                Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.StreamClosed)
                {
                    Role = "server",
                    StreamId = stream.Id,
                    StreamKind = streamKind,
                });
            }
        }
    }

    private async ValueTask ObservePeerUnidirectionalPayloadAsync(
        QuicStream stream,
        Http3StreamDispatcher dispatcher,
        object dispatcherGate,
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
        Http3StreamDispatcher dispatcher,
        object dispatcherGate,
        byte[] initialPayload,
        byte[] buffer,
        CancellationToken cancellationToken)
    {
        Http3FrameReader frameReader = new();
        ProcessPeerControlBytes(frameReader, initialPayload, stream.Id, dispatcher, dispatcherGate);

        while (true)
        {
            int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false);
            if (bytesRead == 0)
            {
                ProcessPeerControlFrames(frameReader.Complete(), stream.Id, dispatcher, dispatcherGate);
                return;
            }

            ProcessPeerControlBytes(frameReader, buffer.AsSpan(0, bytesRead), stream.Id, dispatcher, dispatcherGate);
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
        while (true)
        {
            int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false);
            if (bytesRead == 0)
            {
                return;
            }

            EmitQPackBytesReceived(stream.Id, streamKind, bytesRead);
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
        CancellationToken cancellationToken)
    {
        await using (stream.ConfigureAwait(false))
        {
            try
            {
                Http3Request request = await ReadRequestAsync(stream, cancellationToken).ConfigureAwait(false);
                Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.RequestStarted)
                {
                    Role = "server",
                    StreamId = stream.Id,
                    Method = request.Method,
                    Path = request.Path,
                });
                Http3ServerResponse response = await handler.HandleAsync(request, cancellationToken).ConfigureAwait(false);
                await WriteResponseAsync(stream, response, cancellationToken).ConfigureAwait(false);
                if (response.SendGoAwayAfterResponse)
                {
                    await WriteGoAwayAsync(controlStream, checked((ulong)stream.Id), cancellationToken).ConfigureAwait(false);
                }

                if (response.CloseConnectionAfterResponse)
                {
                    await connection.CloseAsync(0, cancellationToken).ConfigureAwait(false);
                }

                Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.ResponseCompleted)
                {
                    Role = "server",
                    StreamId = stream.Id,
                    StatusCode = response.StatusCode,
                    PayloadLength = response.Body.Length,
                });
                Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.RequestCompleted)
                {
                    Role = "server",
                    StreamId = stream.Id,
                    Method = request.Method,
                    Path = request.Path,
                    StatusCode = response.StatusCode,
                    PayloadLength = response.Body.Length,
                });
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
                await TryWriteResponseAsync(stream, CreateBadRequestResponse(), cancellationToken).ConfigureAwait(false);
            }
            catch (Http3Exception exception)
            {
                EmitError(exception);
                await TryWriteResponseAsync(stream, CreateBadRequestResponse(), cancellationToken).ConfigureAwait(false);
            }
            catch (ArgumentException exception)
            {
                EmitError(exception);
                await TryWriteResponseAsync(stream, CreateBadRequestResponse(), cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.StreamClosed)
                {
                    Role = "server",
                    StreamId = stream.Id,
                    StreamKind = Http3StreamKind.Request,
                });
            }
        }
    }

    private async ValueTask<Http3Request> ReadRequestAsync(QuicStream stream, CancellationToken cancellationToken)
    {
        Http3FrameReader frameReader = new();
        Http3RequestMessageValidator validator = new();
        byte[] buffer = new byte[readBufferSize];

        while (true)
        {
            int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false);
            if (bytesRead == 0)
            {
                foreach (Http3Frame frame in frameReader.Complete())
                {
                    CaptureRequestFrame(frame, validator, stream.Id);
                }

                break;
            }

            foreach (Http3Frame frame in frameReader.Read(buffer.AsSpan(0, bytesRead)))
            {
                CaptureRequestFrame(frame, validator, stream.Id);
            }

            if (TryCreateNoBodyGetRequest(validator.Headers, out Http3Request request))
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

        return CreateRequest(headers);
    }

    private static bool TryCreateNoBodyGetRequest(
        IReadOnlyList<QPackFieldLine>? headers,
        out Http3Request request)
    {
        request = null!;
        if (headers is null)
        {
            return false;
        }

        Http3HeaderValidationResult result = Http3HeaderValidator.ValidateRequestHeaders(headers, receivedDataLength: 0);
        if (result.Method != "GET")
        {
            return false;
        }

        request = new Http3Request(result.Method, result.Scheme ?? string.Empty, result.Authority ?? string.Empty, result.Path ?? string.Empty, headers);
        return true;
    }

    private void CaptureRequestFrame(Http3Frame frame, Http3RequestMessageValidator validator, long streamId)
    {
        EmitFrame(Http3DiagnosticKind.FrameReceived, streamId, frame);
        switch (frame)
        {
            case Http3HeadersFrame headersFrame:
                validator.ReceiveHeaders(QPackDecoder.DecodeFieldSection(headersFrame.EncodedFieldSection));
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

    private void ProcessPeerControlBytes(
        Http3FrameReader frameReader,
        ReadOnlySpan<byte> bytes,
        long streamId,
        Http3StreamDispatcher dispatcher,
        object dispatcherGate)
    {
        if (bytes.IsEmpty)
        {
            return;
        }

        ProcessPeerControlFrames(frameReader.Read(bytes), streamId, dispatcher, dispatcherGate);
    }

    private void ProcessPeerControlFrames(
        IEnumerable<Http3Frame> frames,
        long streamId,
        Http3StreamDispatcher dispatcher,
        object dispatcherGate)
    {
        foreach (Http3Frame frame in frames)
        {
            lock (dispatcherGate)
            {
                dispatcher.ReceiveFrame(checked((ulong)streamId), frame);
            }

            EmitFrame(Http3DiagnosticKind.FrameReceived, streamId, frame);
            if (frame is Http3SettingsFrame)
            {
                Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.SettingsReceived)
                {
                    Role = "server",
                    StreamId = streamId,
                });
            }
        }
    }

    private static Http3Request CreateRequest(IReadOnlyList<QPackFieldLine> headers)
    {
        Http3HeaderValidationResult result = Http3HeaderValidator.ValidateRequestHeaders(headers);
        return new Http3Request(result.Method!, result.Scheme ?? string.Empty, result.Authority ?? string.Empty, result.Path ?? string.Empty, headers);
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

    private async ValueTask WriteResponseAsync(
        QuicStream stream,
        Http3ServerResponse response,
        CancellationToken cancellationToken)
    {
        byte[] headersFrame = Http3FrameWriter.WriteHeaders(EncodeResponseFieldSection(BuildResponseHeaders(response)));
        if (response.Body.IsEmpty)
        {
            await WriteFinalFrameBytesAsync(stream, headersFrame, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            await WriteFrameBytesAsync(stream, headersFrame, cancellationToken).ConfigureAwait(false);
        }

        EmitFrame(Http3DiagnosticKind.FrameSent, stream.Id, Http3FrameType.Headers, headersFrame.Length);
        Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.ResponseStarted)
        {
            Role = "server",
            StreamId = stream.Id,
            StatusCode = response.StatusCode,
        });

        if (!response.Body.IsEmpty)
        {
            await WriteResponseDataFramesAsync(stream, response.Body, response.DataFramePayloadSize, cancellationToken).ConfigureAwait(false);
        }
    }

    private async ValueTask WriteResponseDataFramesAsync(
        QuicStream stream,
        ReadOnlyMemory<byte> body,
        int? dataFramePayloadSize,
        CancellationToken cancellationToken)
    {
        int framePayloadSize = dataFramePayloadSize ?? ResponseDataFrameChunkSize;
        int offset = 0;
        while (offset < body.Length)
        {
            int count = Math.Min(framePayloadSize, body.Length - offset);
            byte[] dataFrame = Http3FrameWriter.WriteData(body.Span.Slice(offset, count));
            if (offset + count == body.Length)
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
    {
        int offset = 0;
        while (offset < frameBytes.Length)
        {
            int count = Math.Min(ResponseWriteChunkSize, frameBytes.Length - offset);
            if (offset + count == frameBytes.Length)
            {
                await stream.WriteFinalAsync(frameBytes, offset, count, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                await stream.WriteAsync(frameBytes, offset, count, cancellationToken).ConfigureAwait(false);
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

    private static IReadOnlyList<QPackFieldLine> BuildResponseHeaders(Http3ServerResponse response)
    {
        ArrayBufferWriter<QPackFieldLine> headers = new();
        WriteField(headers, new QPackFieldLine(":status", response.StatusCode.ToString()));
        foreach (QPackFieldLine header in response.Headers)
        {
            if (header.Name == ":status")
            {
                continue;
            }

            WriteField(headers, header);
        }

        return headers.WrittenSpan.ToArray();
    }

    private static void WriteField(IBufferWriter<QPackFieldLine> writer, QPackFieldLine fieldLine)
    {
        Span<QPackFieldLine> destination = writer.GetSpan(1);
        destination[0] = fieldLine;
        writer.Advance(1);
    }

    private static byte[] EncodeResponseFieldSection(IReadOnlyList<QPackFieldLine> headers)
    {
        ArrayBufferWriter<byte> writer = new();
        WriteBytes(writer, QPackInteger.Encode(0, FieldSectionRequiredInsertCountPrefixBits));
        WriteBytes(writer, QPackInteger.Encode(0, FieldSectionBasePrefixBits));

        foreach (QPackFieldLine header in headers)
        {
            if (header.Name == ":status")
            {
                WriteLiteralWithStaticNameReference(writer, StatusStaticNameIndex, header.Value);
                continue;
            }

            int staticFieldIndex = FindStaticFieldLineIndex(header);
            if (staticFieldIndex >= 0)
            {
                WriteBytes(writer, QPackInteger.Encode(checked((ulong)staticFieldIndex), IndexedFieldPrefixBits, StaticIndexedFieldPrefix));
                continue;
            }

            int staticNameIndex = FindStaticNameIndex(header.Name);
            if (staticNameIndex >= 0)
            {
                WriteLiteralWithStaticNameReference(writer, staticNameIndex, header.Value);
                continue;
            }

            WriteBytes(writer, QPackInteger.Encode(checked((ulong)HeaderTextEncoding.GetByteCount(header.Name)), LiteralNamePrefixBits - 1, LiteralWithLiteralNamePrefix));
            WriteRawString(writer, header.Name);
            WriteStringLiteral(writer, header.Value);
        }

        return writer.WrittenSpan.ToArray();
    }

    private static void WriteLiteralWithStaticNameReference(IBufferWriter<byte> writer, int staticNameIndex, string value)
    {
        WriteBytes(writer, QPackInteger.Encode(checked((ulong)staticNameIndex), StaticNameReferencePrefixBits, LiteralWithStaticNameReferencePrefix));
        WriteStringLiteral(writer, value);
    }

    private static void WriteStringLiteral(IBufferWriter<byte> writer, string value)
    {
        WriteBytes(writer, QPackInteger.Encode(checked((ulong)HeaderTextEncoding.GetByteCount(value)), StringLiteralPrefixBits - 1));
        WriteRawString(writer, value);
    }

    private static void WriteRawString(IBufferWriter<byte> writer, string value)
    {
        byte[] bytes = HeaderTextEncoding.GetBytes(value);
        Span<byte> destination = writer.GetSpan(bytes.Length);
        bytes.CopyTo(destination);
        writer.Advance(bytes.Length);
    }

    private static void WriteBytes(IBufferWriter<byte> writer, ReadOnlySpan<byte> source)
    {
        Span<byte> destination = writer.GetSpan(source.Length);
        source.CopyTo(destination);
        writer.Advance(source.Length);
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
        for (int index = 0; index < QPackStaticTable.Count; index++)
        {
            if (QPackStaticTable.TryGet(index, out QPackFieldLine candidate)
                && StringComparer.Ordinal.Equals(candidate.Name, fieldLine.Name)
                && StringComparer.Ordinal.Equals(candidate.Value, fieldLine.Value))
            {
                return index;
            }
        }

        return -1;
    }

    private static int FindStaticNameIndex(string name)
    {
        for (int index = 0; index < QPackStaticTable.Count; index++)
        {
            if (QPackStaticTable.TryGet(index, out QPackFieldLine candidate)
                && StringComparer.Ordinal.Equals(candidate.Name, name))
            {
                return index;
            }
        }

        return -1;
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

    private void EmitFrame(Http3DiagnosticKind kind, long streamId, Http3FrameType frameType, int payloadLength)
    {
        Emit(new Http3DiagnosticEvent(kind)
        {
            Role = "server",
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
            Role = "server",
            StreamId = streamId,
            FrameType = Enum.IsDefined(typeof(Http3FrameType), (long)frame.Type) ? (Http3FrameType)frame.Type : null,
            RawFrameType = frame.Type,
            PayloadLength = frame.Payload.Length,
        });
    }

    private void EmitQPackBytesReceived(long streamId, Http3StreamKind streamKind, int payloadLength)
    {
        if (payloadLength == 0)
        {
            return;
        }

        Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.QPackInstructionReceived)
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
        Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.Error)
        {
            Role = "server",
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
}
