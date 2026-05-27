namespace Incursa.Quic.Dns;

/// <summary>
/// Represents a DNS over QUIC protocol failure.
/// </summary>
public sealed class DoqException : Exception
{
    /// <summary>
    /// Initializes a new instance of the <see cref="DoqException"/> class.
    /// </summary>
    public DoqException(DoqErrorCode errorCode, string message)
        : base(message)
    {
        ErrorCode = errorCode;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="DoqException"/> class.
    /// </summary>
    public DoqException(DoqErrorCode errorCode, string message, Exception innerException)
        : base(message, innerException)
    {
        ErrorCode = errorCode;
    }

    /// <summary>
    /// Gets the DoQ error code associated with the failure.
    /// </summary>
    public DoqErrorCode ErrorCode { get; }
}
