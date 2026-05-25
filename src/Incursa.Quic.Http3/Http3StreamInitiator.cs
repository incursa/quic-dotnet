namespace Incursa.Quic.Http3;

/// <summary>
/// Identifies the QUIC endpoint that initiated a stream.
/// </summary>
public enum Http3StreamInitiator
{
    /// <summary>
    /// The stream was initiated by the client.
    /// </summary>
    Client,

    /// <summary>
    /// The stream was initiated by the server.
    /// </summary>
    Server,
}
