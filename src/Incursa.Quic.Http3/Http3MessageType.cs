namespace Incursa.Quic.Http3;

/// <summary>
/// Identifies the HTTP/3 message kind being validated.
/// </summary>
public enum Http3MessageType
{
    /// <summary>
    /// A request message.
    /// </summary>
    Request,

    /// <summary>
    /// A response message.
    /// </summary>
    Response,
}
