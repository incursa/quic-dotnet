using System.Threading;

namespace Incursa.Quic;

/// <summary>
/// Shared connection settings used by the consumer-facing QUIC facade.
/// </summary>
public abstract class QuicConnectionOptions
{
    private const int DefaultConnectionReceiveWindow = 16 * 1024 * 1024;
    private const int DefaultStreamReceiveWindow = 64 * 1024;
    private static readonly TimeSpan DefaultHandshakeTimeout = TimeSpan.FromSeconds(10);

    private QuicReceiveWindowSizes initialReceiveWindowSizes = new();

    /// <summary>
    /// Prevents external derivation outside of the assembly.
    /// </summary>
    internal QuicConnectionOptions()
    {
        DefaultCloseErrorCode = -1;
        DefaultStreamErrorCode = -1;
        HandshakeTimeout = DefaultHandshakeTimeout;
        IdleTimeout = TimeSpan.Zero;
        KeepAliveInterval = Timeout.InfiniteTimeSpan;
        MaxInboundBidirectionalStreams = 0;
        MaxInboundUnidirectionalStreams = 0;
        initialReceiveWindowSizes = new QuicReceiveWindowSizes
        {
            Connection = DefaultConnectionReceiveWindow,
            LocallyInitiatedBidirectionalStream = DefaultStreamReceiveWindow,
            RemotelyInitiatedBidirectionalStream = DefaultStreamReceiveWindow,
            UnidirectionalStream = DefaultStreamReceiveWindow,
        };
    }

    /// <summary>
    /// Gets or sets the default close error code used by the connection on dispose.
    /// </summary>
    public long DefaultCloseErrorCode { get; set; }

    /// <summary>
    /// Gets or sets the default stream error code used by the connection on dispose.
    /// </summary>
    public long DefaultStreamErrorCode { get; set; }

    /// <summary>
    /// Gets or sets the handshake timeout.
    /// </summary>
    public TimeSpan HandshakeTimeout { get; set; }

    /// <summary>
    /// Gets or sets the idle timeout.
    /// </summary>
    public TimeSpan IdleTimeout { get; set; }

    /// <summary>
    /// Gets or sets the receive-window sizes used when the connection is created.
    /// </summary>
    public QuicReceiveWindowSizes InitialReceiveWindowSizes
    {
        get => initialReceiveWindowSizes;
        set => initialReceiveWindowSizes = value ?? throw new ArgumentNullException(nameof(value));
    }

    /// <summary>
    /// Gets or sets the keep-alive interval.
    /// </summary>
    public TimeSpan KeepAliveInterval { get; set; }

    /// <summary>
    /// Gets or sets the maximum number of inbound bidirectional streams.
    /// </summary>
    public int MaxInboundBidirectionalStreams { get; set; }

    /// <summary>
    /// Gets or sets the maximum number of inbound unidirectional streams.
    /// </summary>
    public int MaxInboundUnidirectionalStreams { get; set; }
}

