using System.Net.Security;

namespace Incursa.Quic;

/// <summary>
/// Server-side connection options selected by <see cref="QuicListenerOptions.ConnectionOptionsCallback"/>.
/// </summary>
public sealed class QuicServerConnectionOptions : QuicConnectionOptions
{
    private const int DefaultMaxInboundBidirectionalStreams = 100;
    private const int DefaultMaxInboundUnidirectionalStreams = 10;

    /// <summary>
    /// Initializes a new server connection options bag.
    /// </summary>
    public QuicServerConnectionOptions()
    {
        MaxInboundBidirectionalStreams = DefaultMaxInboundBidirectionalStreams;
        MaxInboundUnidirectionalStreams = DefaultMaxInboundUnidirectionalStreams;
    }

    /// <summary>
    /// Gets or sets the server authentication options.
    /// </summary>
    public SslServerAuthenticationOptions ServerAuthenticationOptions { get; set; } = null!;
}
