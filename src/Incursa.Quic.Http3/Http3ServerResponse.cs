// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Incursa.Qpack;

namespace Incursa.Quic.Http3;

/// <summary>
/// Represents a response emitted by the minimal HTTP/3 server.
/// </summary>
public sealed class Http3ServerResponse
{
    private const int MinimumStatusCode = 100;
    private const int MaximumStatusCode = 999;
    private byte[]? cachedHeadersFrame;
    private byte[]? cachedSingleDataFrame;

    /// <summary>
    /// Initializes a new instance of the <see cref="Http3ServerResponse" /> class.
    /// </summary>
    public Http3ServerResponse(
        int statusCode,
        ReadOnlyMemory<byte> body,
        IEnumerable<QPackFieldLine>? headers = null,
        int? dataFramePayloadSize = null,
        bool sendGoAwayAfterResponse = false,
        bool closeConnectionAfterResponse = false,
        IAsyncEnumerable<ReadOnlyMemory<byte>>? streamingBody = null)
        : this(
            statusCode,
            body,
            headers,
            dataFramePayloadSize,
            sendGoAwayAfterResponse,
            closeConnectionAfterResponse,
            streamingBody,
            copyBody: true)
    {
    }

    private Http3ServerResponse(
        int statusCode,
        ReadOnlyMemory<byte> body,
        IEnumerable<QPackFieldLine>? headers,
        int? dataFramePayloadSize,
        bool sendGoAwayAfterResponse,
        bool closeConnectionAfterResponse,
        IAsyncEnumerable<ReadOnlyMemory<byte>>? streamingBody,
        bool copyBody,
        bool copyHeaders = true,
        bool cacheEncodedHeaders = false)
    {
        if (statusCode < MinimumStatusCode || statusCode > MaximumStatusCode)
        {
            throw new ArgumentOutOfRangeException(nameof(statusCode));
        }

        if (dataFramePayloadSize <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(dataFramePayloadSize));
        }

        StatusCode = statusCode;
        Body = copyBody ? body.ToArray() : body;
        if (headers is null)
        {
            Headers = [];
        }
        else if (!copyHeaders && headers is IReadOnlyList<QPackFieldLine> list)
        {
            Headers = list;
        }
        else
        {
            Headers = headers.ToArray();
        }

        DataFramePayloadSize = dataFramePayloadSize;
        SendGoAwayAfterResponse = sendGoAwayAfterResponse;
        CloseConnectionAfterResponse = closeConnectionAfterResponse;
        StreamingBody = streamingBody;
        CacheEncodedHeaders = cacheEncodedHeaders;
    }

    /// <summary>
    /// Creates a response whose DATA frames are produced asynchronously while the stream is being written.
    /// </summary>
    public static Http3ServerResponse CreateStreaming(
        int statusCode,
        IAsyncEnumerable<ReadOnlyMemory<byte>> body,
        IEnumerable<QPackFieldLine>? headers = null,
        int? dataFramePayloadSize = null)
    {
        ArgumentNullException.ThrowIfNull(body);
        return new Http3ServerResponse(
            statusCode,
            ReadOnlyMemory<byte>.Empty,
            headers,
            dataFramePayloadSize,
            streamingBody: body);
    }

    /// <summary>
    /// Creates a response over caller-owned immutable body memory without copying it.
    /// </summary>
    public static Http3ServerResponse CreateFromImmutableBody(
        int statusCode,
        ReadOnlyMemory<byte> body,
        IEnumerable<QPackFieldLine>? headers = null,
        int? dataFramePayloadSize = null,
        bool sendGoAwayAfterResponse = false,
        bool closeConnectionAfterResponse = false)
    {
        return new Http3ServerResponse(
            statusCode,
            body,
            headers,
            dataFramePayloadSize,
            sendGoAwayAfterResponse,
            closeConnectionAfterResponse,
            streamingBody: null,
            copyBody: false,
            cacheEncodedHeaders: true);
    }

    /// <summary>
    /// Creates a response over caller-owned immutable body and header collections without copying them.
    /// </summary>
    public static Http3ServerResponse CreateFromImmutableBodyAndHeaders(
        int statusCode,
        ReadOnlyMemory<byte> body,
        IReadOnlyList<QPackFieldLine>? headers = null,
        int? dataFramePayloadSize = null,
        bool sendGoAwayAfterResponse = false,
        bool closeConnectionAfterResponse = false)
    {
        return new Http3ServerResponse(
            statusCode,
            body,
            headers,
            dataFramePayloadSize,
            sendGoAwayAfterResponse,
            closeConnectionAfterResponse,
            streamingBody: null,
            copyBody: false,
            copyHeaders: false,
            cacheEncodedHeaders: true);
    }

    /// <summary>
    /// Gets the HTTP status code.
    /// </summary>
    public int StatusCode { get; }

    /// <summary>
    /// Gets response headers excluding :status.
    /// </summary>
    public IReadOnlyList<QPackFieldLine> Headers { get; }

    /// <summary>
    /// Gets response body bytes.
    /// </summary>
    public ReadOnlyMemory<byte> Body { get; }

    /// <summary>
    /// Gets an optional asynchronous body source for streaming responses.
    /// </summary>
    public IAsyncEnumerable<ReadOnlyMemory<byte>>? StreamingBody { get; }

    /// <summary>
    /// Gets an optional per-response DATA frame payload size used by the minimal server.
    /// </summary>
    public int? DataFramePayloadSize { get; }

    /// <summary>
    /// Gets whether the minimal server should emit GOAWAY on the connection control stream after this response.
    /// </summary>
    public bool SendGoAwayAfterResponse { get; }

    /// <summary>
    /// Gets whether the minimal server should close the QUIC connection after this response.
    /// </summary>
    public bool CloseConnectionAfterResponse { get; }

    internal bool CacheEncodedHeaders { get; }

    internal byte[]? GetCachedHeadersFrame() => Volatile.Read(ref cachedHeadersFrame);

    internal byte[] CacheHeadersFrame(byte[] headersFrame) =>
        Interlocked.CompareExchange(ref cachedHeadersFrame, headersFrame, null) ?? headersFrame;

    internal byte[]? GetCachedSingleDataFrame() => Volatile.Read(ref cachedSingleDataFrame);

    internal byte[] CacheSingleDataFrame(byte[] dataFrame) =>
        Interlocked.CompareExchange(ref cachedSingleDataFrame, dataFrame, null) ?? dataFrame;
}
