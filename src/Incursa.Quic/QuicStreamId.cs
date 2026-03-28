namespace Incursa.Quic;

/// <summary>
/// A parsed QUIC stream identifier.
/// </summary>
public readonly struct QuicStreamId
{
    private readonly ulong value;

    internal QuicStreamId(ulong value)
    {
        this.value = value;
    }

    /// <summary>
    /// Gets the decoded stream identifier value.
    /// </summary>
    public ulong Value => value;

    /// <summary>
    /// Gets the stream type classification derived from the low-order bits.
    /// </summary>
    public QuicStreamType StreamType => (QuicStreamType)(value & 0x03);

    /// <summary>
    /// Gets whether the stream was initiated by a client.
    /// </summary>
    public bool IsClientInitiated => (value & 0x01) == 0;

    /// <summary>
    /// Gets whether the stream was initiated by a server.
    /// </summary>
    public bool IsServerInitiated => !IsClientInitiated;

    /// <summary>
    /// Gets whether the stream is bidirectional.
    /// </summary>
    public bool IsBidirectional => (value & 0x02) == 0;

    /// <summary>
    /// Gets whether the stream is unidirectional.
    /// </summary>
    public bool IsUnidirectional => !IsBidirectional;
}
