namespace Incursa.Quic.Dns;

/// <summary>
/// Represents the DNS response payload produced for one DoQ query.
/// </summary>
public readonly struct DoqQueryResult
{
    /// <summary>
    /// Initializes a new instance of the <see cref="DoqQueryResult"/> struct.
    /// </summary>
    public DoqQueryResult(ReadOnlyMemory<byte> response)
    {
        Response = response;
    }

    /// <summary>
    /// Gets the DNS response payload without the DoQ length prefix.
    /// </summary>
    public ReadOnlyMemory<byte> Response { get; }
}
