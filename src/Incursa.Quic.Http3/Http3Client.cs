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
    private const string MethodGet = "GET";
    private readonly QuicConnection connection;
    private readonly Http3Settings localSettings;
    private readonly string? userAgent;
    private readonly int readBufferSize;
    private readonly bool completeResponseOnContentLength;
    private QuicStream? controlStream;
    private QuicStream? qpackEncoderStream;
    private QuicStream? qpackDecoderStream;
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
        completeResponseOnContentLength = options.CompleteResponseOnContentLength;
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

        await using QuicStream requestStream = await connection
            .OpenOutboundStreamAsync(QuicStreamType.Bidirectional, cancellationToken)
            .ConfigureAwait(false);

        byte[] requestHeaders = QPackEncoder.EncodeFieldSection(BuildGetRequestHeaders(requestUri));
        byte[] headersFrame = Http3FrameWriter.WriteHeaders(requestHeaders);
        await requestStream.WriteAsync(headersFrame, 0, headersFrame.Length, cancellationToken).ConfigureAwait(false);
        await requestStream.CompleteWritesAsync(cancellationToken).ConfigureAwait(false);

        return await ReadResponseAsync(requestStream, cancellationToken).ConfigureAwait(false);
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

        await connection.DisposeAsync().ConfigureAwait(false);
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

        qpackEncoderStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Unidirectional, cancellationToken).ConfigureAwait(false);
        await WriteStreamTypeAsync(qpackEncoderStream, Http3StreamType.QPackEncoder, cancellationToken).ConfigureAwait(false);

        qpackDecoderStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Unidirectional, cancellationToken).ConfigureAwait(false);
        await WriteStreamTypeAsync(qpackDecoderStream, Http3StreamType.QPackDecoder, cancellationToken).ConfigureAwait(false);
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
                    ProcessResponseFrame(frame, validator, body);
                }

                break;
            }

            foreach (Http3Frame frame in frameReader.Read(buffer.AsSpan(0, bytesRead)))
            {
                ProcessResponseFrame(frame, validator, body);
            }

            if (completeResponseOnContentLength &&
                TryCompleteOnContentLength(validator, body.WrittenCount))
            {
                break;
            }
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
        return new Http3Response(statusCode, headers, body.WrittenSpan.ToArray(), streamCompleted);
    }

    private static bool TryCompleteOnContentLength(
        Http3ResponseSequenceValidator validator,
        int receivedBodyLength)
    {
        IReadOnlyList<QPackFieldLine>? headers = validator.FinalResponseHeaders;
        if (headers is null)
        {
            return false;
        }

        if (!TryGetContentLength(headers, out ulong contentLength))
        {
            return false;
        }

        ulong receivedLength = checked((ulong)receivedBodyLength);
        if (receivedLength > contentLength)
        {
            throw new Http3Exception(Http3ErrorCode.MessageError, "The HTTP/3 response body exceeded Content-Length.");
        }

        return receivedLength == contentLength;
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

    private static void ProcessResponseFrame(Http3Frame frame, Http3ResponseSequenceValidator validator, IBufferWriter<byte> body)
    {
        switch (frame)
        {
            case Http3HeadersFrame headersFrame:
                validator.ReceiveHeaders(QPackDecoder.DecodeFieldSection(headersFrame.EncodedFieldSection));
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
}
