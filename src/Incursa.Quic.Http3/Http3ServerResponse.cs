using Incursa.Qpack;

namespace Incursa.Quic.Http3;

/// <summary>
/// Represents a response emitted by the minimal HTTP/3 server.
/// </summary>
public sealed class Http3ServerResponse
{
    private const int MinimumStatusCode = 100;
    private const int MaximumStatusCode = 999;

    /// <summary>
    /// Initializes a new instance of the <see cref="Http3ServerResponse" /> class.
    /// </summary>
    public Http3ServerResponse(
        int statusCode,
        ReadOnlyMemory<byte> body,
        IEnumerable<QPackFieldLine>? headers = null,
        int? dataFramePayloadSize = null,
        bool sendGoAwayAfterResponse = false,
        bool closeConnectionAfterResponse = false)
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
        Body = body.ToArray();
        Headers = headers?.ToArray() ?? [];
        DataFramePayloadSize = dataFramePayloadSize;
        SendGoAwayAfterResponse = sendGoAwayAfterResponse;
        CloseConnectionAfterResponse = closeConnectionAfterResponse;
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
}
