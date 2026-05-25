namespace Incursa.Quic.Http3;

/// <summary>
/// Represents an HTTP/3 protocol error that can be converted to a connection or stream close.
/// </summary>
public sealed class Http3Exception : IOException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="Http3Exception" /> class.
    /// </summary>
    public Http3Exception(Http3ErrorCode errorCode, string message)
        : base(message)
    {
        ErrorCode = errorCode;
    }

    /// <summary>
    /// Gets the HTTP/3 error code.
    /// </summary>
    public Http3ErrorCode ErrorCode { get; }
}
