using System.IO;

namespace Incursa.Qpack;

/// <summary>
/// Represents a QPACK decoding or encoding failure mapped to an RFC 9204 error code.
/// </summary>
public sealed class QPackException : IOException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="QPackException"/> class.
    /// </summary>
    public QPackException(QPackErrorCode errorCode, string message)
        : base(message)
    {
        ErrorCode = errorCode;
    }

    /// <summary>
    /// Gets the QPACK error code associated with the failure.
    /// </summary>
    public QPackErrorCode ErrorCode { get; }
}
