namespace Incursa.Quic.Dns;

/// <summary>
/// Describes a DNS over QUIC query delivered to a server handler.
/// </summary>
public sealed class DoqQueryContext
{
    /// <summary>
    /// Initializes a new instance of the <see cref="DoqQueryContext"/> class.
    /// </summary>
    public DoqQueryContext(long streamId, ReadOnlyMemory<byte> query)
    {
        StreamId = streamId;
        Query = query;
    }

    /// <summary>
    /// Gets the QUIC stream ID carrying the DoQ transaction.
    /// </summary>
    public long StreamId { get; }

    /// <summary>
    /// Gets the DNS query payload without the DoQ length prefix.
    /// </summary>
    public ReadOnlyMemory<byte> Query { get; }
}
