namespace Incursa.Quic;

/// <summary>
/// Identifies the endpoint role for transport-parameter parsing and formatting.
/// </summary>
public enum QuicTransportParameterRole
{
    /// <summary>
    /// The local endpoint is a client.
    /// </summary>
    Client = 0,

    /// <summary>
    /// The local endpoint is a server.
    /// </summary>
    Server = 1,
}
