namespace Incursa.Quic.Dns;

/// <summary>
/// DNS over QUIC server policy options.
/// </summary>
public sealed class DoqServerOptions
{
    private int maxDanglingStreams;
    private int maxCancellationRequests;

    /// <summary>
    /// Gets or sets the maximum number of concurrently accepted query streams that have not completed.
    /// A value of zero disables the adapter-level limit.
    /// </summary>
    public int MaxDanglingStreams
    {
        get => maxDanglingStreams;
        set
        {
            ArgumentOutOfRangeException.ThrowIfNegative(value);
            maxDanglingStreams = value;
        }
    }

    /// <summary>
    /// Gets or sets the maximum number of request cancellation/reset events allowed on a connection.
    /// A value of zero disables the adapter-level limit.
    /// </summary>
    public int MaxCancellationRequests
    {
        get => maxCancellationRequests;
        set
        {
            ArgumentOutOfRangeException.ThrowIfNegative(value);
            maxCancellationRequests = value;
        }
    }
}
