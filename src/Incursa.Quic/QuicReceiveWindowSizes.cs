namespace Incursa.Quic;

/// <summary>
/// Receive-window settings for a connection and its streams.
/// </summary>
public sealed class QuicReceiveWindowSizes
{
    private const int DefaultConnectionReceiveWindow = 16 * 1024 * 1024;
    private const int DefaultStreamReceiveWindow = 64 * 1024;

    /// <summary>
    /// Initializes a new instance of the <see cref="QuicReceiveWindowSizes"/> class.
    /// </summary>
    public QuicReceiveWindowSizes()
    {
        Connection = DefaultConnectionReceiveWindow;
        LocallyInitiatedBidirectionalStream = DefaultStreamReceiveWindow;
        RemotelyInitiatedBidirectionalStream = DefaultStreamReceiveWindow;
        UnidirectionalStream = DefaultStreamReceiveWindow;
    }

    /// <summary>
    /// Gets or sets the connection-level receive window.
    /// </summary>
    public int Connection { get; set; }

    /// <summary>
    /// Gets or sets the receive window for locally initiated bidirectional streams.
    /// </summary>
    public int LocallyInitiatedBidirectionalStream { get; set; }

    /// <summary>
    /// Gets or sets the receive window for remotely initiated bidirectional streams.
    /// </summary>
    public int RemotelyInitiatedBidirectionalStream { get; set; }

    /// <summary>
    /// Gets or sets the receive window for unidirectional streams.
    /// </summary>
    public int UnidirectionalStream { get; set; }
}

