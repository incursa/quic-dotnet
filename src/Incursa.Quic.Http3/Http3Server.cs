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
                await OpenRequiredUnidirectionalStreamsAsync(connection, cancellationToken).ConfigureAwait(false);
                await AcceptStreamsAsync(connection, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException exception) when (cancellationToken.IsCancellationRequested)
            {
                SuppressExpectedException(exception);
            }
            catch (ObjectDisposedException exception) when (Volatile.Read(ref disposed) != 0)
            {
                SuppressExpectedException(exception);
            }
        }
    }

    private async ValueTask OpenRequiredUnidirectionalStreamsAsync(QuicConnection connection, CancellationToken cancellationToken)
    {
        QuicStream controlStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Unidirectional, cancellationToken).ConfigureAwait(false);
        byte[] initialControlStream = Http3SettingsWriter.WriteInitialControlStream(localSettings);
        await controlStream.WriteAsync(initialControlStream, 0, initialControlStream.Length, cancellationToken).ConfigureAwait(false);

        QuicStream qpackEncoderStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Unidirectional, cancellationToken).ConfigureAwait(false);
        await WriteStreamTypeAsync(qpackEncoderStream, Http3StreamType.QPackEncoder, cancellationToken).ConfigureAwait(false);

        QuicStream qpackDecoderStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Unidirectional, cancellationToken).ConfigureAwait(false);
        await WriteStreamTypeAsync(qpackDecoderStream, Http3StreamType.QPackDecoder, cancellationToken).ConfigureAwait(false);
    }

    private async Task AcceptStreamsAsync(QuicConnection connection, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            QuicStream stream = await connection.AcceptInboundStreamAsync(cancellationToken).ConfigureAwait(false);
            _ = stream.Type == QuicStreamType.Bidirectional
                ? HandleRequestStreamAsync(stream, cancellationToken)
                : ObservePeerUnidirectionalStreamAsync(stream, cancellationToken);
        }
    }

    private async Task ObservePeerUnidirectionalStreamAsync(QuicStream stream, CancellationToken cancellationToken)
    {
        await using (stream.ConfigureAwait(false))
        {
            byte[] buffer = new byte[readBufferSize];
            try
            {
                int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false);
                if (bytesRead == 0)
                {
                    return;
                }

                _ = Http3VariableLengthInteger.TryParse(buffer.AsSpan(0, bytesRead), out _, out _);
            }
            catch (OperationCanceledException exception) when (cancellationToken.IsCancellationRequested)
            {
                SuppressExpectedException(exception);
            }
            catch (QuicException exception)
            {
                SuppressExpectedException(exception);
            }
        }
    }

    private async Task HandleRequestStreamAsync(QuicStream stream, CancellationToken cancellationToken)
    {
        await using (stream.ConfigureAwait(false))
        {
            try
            {
                Http3Request request = await ReadRequestAsync(stream, cancellationToken).ConfigureAwait(false);
                Http3ServerResponse response = await handler.HandleAsync(request, cancellationToken).ConfigureAwait(false);
                await WriteResponseAsync(stream, response, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException exception) when (cancellationToken.IsCancellationRequested)
            {
                SuppressExpectedException(exception);
            }
            catch (QuicException exception)
            {
                SuppressExpectedException(exception);
            }
            catch (QPackException)
            {
                await TryWriteResponseAsync(stream, CreateBadRequestResponse(), cancellationToken).ConfigureAwait(false);
            }
            catch (Http3Exception)
            {
                await TryWriteResponseAsync(stream, CreateBadRequestResponse(), cancellationToken).ConfigureAwait(false);
            }
            catch (ArgumentException)
            {
                await TryWriteResponseAsync(stream, CreateBadRequestResponse(), cancellationToken).ConfigureAwait(false);
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
                    CaptureRequestFrame(frame, validator);
                }

                break;
            }

            foreach (Http3Frame frame in frameReader.Read(buffer.AsSpan(0, bytesRead)))
            {
                CaptureRequestFrame(frame, validator);
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

    private static void CaptureRequestFrame(Http3Frame frame, Http3RequestMessageValidator validator)
    {
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

    private static Http3Request CreateRequest(IReadOnlyList<QPackFieldLine> headers)
    {
        Http3HeaderValidationResult result = Http3HeaderValidator.ValidateRequestHeaders(headers);
        return new Http3Request(result.Method!, result.Scheme ?? string.Empty, result.Authority ?? string.Empty, result.Path ?? string.Empty, headers);
    }

    private static async ValueTask TryWriteResponseAsync(
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

    private static async ValueTask WriteResponseAsync(
        QuicStream stream,
        Http3ServerResponse response,
        CancellationToken cancellationToken)
    {
        byte[] headersFrame = Http3FrameWriter.WriteHeaders(EncodeResponseFieldSection(BuildResponseHeaders(response)));
        await WriteFrameBytesAsync(stream, headersFrame, cancellationToken).ConfigureAwait(false);

        if (!response.Body.IsEmpty)
        {
            byte[] dataFrame = Http3FrameWriter.WriteData(response.Body.Span);
            await WriteFrameBytesAsync(stream, dataFrame, cancellationToken).ConfigureAwait(false);
        }

        await stream.CompleteWritesAsync(cancellationToken).ConfigureAwait(false);
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
}
