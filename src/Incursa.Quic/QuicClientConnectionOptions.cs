using System.Net;
using System.Net.Security;

namespace Incursa.Quic;

/// <summary>
/// Client-side connection options consumed by <see cref="QuicConnection.ConnectAsync(QuicClientConnectionOptions, CancellationToken)"/>.
/// </summary>
public sealed class QuicClientConnectionOptions : QuicConnectionOptions
{
    /// <summary>
    /// Gets or sets the client authentication options.
    /// </summary>
    public SslClientAuthenticationOptions ClientAuthenticationOptions { get; set; } = null!;

    /// <summary>
    /// Gets or sets the optional local endpoint to bind before connecting.
    /// </summary>
    public IPEndPoint? LocalEndPoint { get; set; }

    /// <summary>
    /// Gets or sets the narrow peer-certificate policy carrier used by the managed client exact-match floor.
    /// </summary>
    public QuicPeerCertificatePolicy? PeerCertificatePolicy { get; set; }

    /// <summary>
    /// Gets or sets the remote endpoint to connect.
    /// </summary>
    public EndPoint RemoteEndPoint { get; set; } = null!;
}
