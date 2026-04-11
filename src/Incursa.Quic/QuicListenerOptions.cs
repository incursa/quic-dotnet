using System.Net;
using System.Net.Security;

namespace Incursa.Quic;

/// <summary>
/// Listener configuration for the public server entry surface.
/// </summary>
public sealed class QuicListenerOptions
{
    private const int DefaultListenBacklog = 512;

    /// <summary>
    /// Initializes a new listener options bag.
    /// </summary>
    public QuicListenerOptions()
    {
    }

    /// <summary>
    /// Gets or sets the local endpoint to bind.
    /// </summary>
    public IPEndPoint ListenEndPoint { get; set; } = null!;

    /// <summary>
    /// Gets or sets the application protocols the listener will accept.
    /// </summary>
    public List<SslApplicationProtocol> ApplicationProtocols { get; set; } = null!;

    /// <summary>
    /// Gets or sets the backlog for pending connections.
    /// </summary>
    public int ListenBacklog { get; set; }

    /// <summary>
    /// Gets or sets the narrow server-side connection-options callback.
    /// </summary>
    public Func<QuicConnection, SslClientHelloInfo, CancellationToken, ValueTask<QuicServerConnectionOptions>> ConnectionOptionsCallback { get; set; } = null!;

    internal void Validate(string argumentName)
    {
        if (ListenEndPoint is null)
        {
            throw new ArgumentNullException(argumentName);
        }

        if (ApplicationProtocols is null)
        {
            throw new ArgumentNullException(argumentName);
        }

        if (ApplicationProtocols.Count == 0)
        {
            throw new ArgumentException("At least one application protocol is required.", argumentName);
        }

        if (ConnectionOptionsCallback is null)
        {
            throw new ArgumentNullException(argumentName);
        }

        if (ListenBacklog < 0)
        {
            throw new ArgumentOutOfRangeException(argumentName);
        }

        if (ListenBacklog == 0)
        {
            ListenBacklog = DefaultListenBacklog;
        }
    }
}
