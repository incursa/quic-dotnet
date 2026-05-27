namespace Incursa.Quic.Dns;

/// <summary>
/// DNS over QUIC application error codes registered by RFC 9250.
/// </summary>
public enum DoqErrorCode : long
{
    /// <summary>
    /// No error occurred.
    /// </summary>
    NoError = 0x0,

    /// <summary>
    /// The endpoint encountered an internal error and cannot continue the transaction or connection.
    /// </summary>
    InternalError = 0x1,

    /// <summary>
    /// The endpoint encountered a DoQ protocol error and is aborting the connection.
    /// </summary>
    ProtocolError = 0x2,

    /// <summary>
    /// The client cancelled an outstanding transaction.
    /// </summary>
    RequestCancelled = 0x3,

    /// <summary>
    /// The endpoint is closing the connection because of excessive load.
    /// </summary>
    ExcessiveLoad = 0x4,

    /// <summary>
    /// No more specific DoQ error code applies.
    /// </summary>
    UnspecifiedError = 0x5,

    /// <summary>
    /// Reserved value available for tests.
    /// </summary>
    ErrorReserved = 0xd098ea5e,
}
