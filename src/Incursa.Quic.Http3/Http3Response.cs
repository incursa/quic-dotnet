using Incursa.Qpack;

namespace Incursa.Quic.Http3;

/// <summary>
/// Represents a complete response received by the minimal HTTP/3 client.
/// </summary>
public sealed class Http3Response
{
    /// <summary>
    /// Initializes a new instance of the <see cref="Http3Response" /> class.
    /// </summary>
    public Http3Response(int statusCode, IReadOnlyList<QPackFieldLine> headers, byte[] body, bool streamCompleted)
    {
        Headers = headers ?? throw new ArgumentNullException(nameof(headers));
        Body = body ?? throw new ArgumentNullException(nameof(body));
        StatusCode = statusCode;
        StreamCompleted = streamCompleted;
    }

    /// <summary>
    /// Gets the response status code from the :status pseudo-field.
    /// </summary>
    public int StatusCode { get; }

    /// <summary>
    /// Gets the decoded response header field lines in wire order.
    /// </summary>
    public IReadOnlyList<QPackFieldLine> Headers { get; }

    /// <summary>
    /// Gets the concatenated response DATA payload.
    /// </summary>
    public byte[] Body { get; }

    /// <summary>
    /// Gets whether the response request stream reached FIN cleanly.
    /// </summary>
    public bool StreamCompleted { get; }
}
