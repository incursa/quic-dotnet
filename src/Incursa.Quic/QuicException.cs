using System.IO;

namespace Incursa.Quic;

/// <summary>
/// Exception raised for QUIC terminal-state failures.
/// </summary>
public sealed class QuicException : IOException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="QuicException"/> class.
    /// </summary>
    public QuicException(QuicError error, long? applicationErrorCode, string message)
        : this(error, applicationErrorCode, null, message, null)
    {
    }

    internal QuicException(QuicError error, long? applicationErrorCode, long? transportErrorCode, string message)
        : this(error, applicationErrorCode, transportErrorCode, message, null)
    {
    }

    internal QuicException(QuicError error, long? applicationErrorCode, string message, Exception? innerException)
        : this(error, applicationErrorCode, null, message, innerException)
    {
    }

    internal QuicException(QuicError error, long? applicationErrorCode, long? transportErrorCode, string message, Exception? innerException)
        : base(message, innerException)
    {
        QuicError = error;
        ApplicationErrorCode = applicationErrorCode;
        TransportErrorCode = transportErrorCode;
    }

    /// <summary>
    /// Gets the QUIC error classification.
    /// </summary>
    public QuicError QuicError { get; }

    /// <summary>
    /// Gets the application error code associated with the exception.
    /// </summary>
    public long? ApplicationErrorCode { get; }

    /// <summary>
    /// Gets the transport error code associated with the exception.
    /// </summary>
    public long? TransportErrorCode { get; }
}

