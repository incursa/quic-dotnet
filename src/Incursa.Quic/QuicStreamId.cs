namespace Incursa.Quic;

/// <summary>
/// A parsed QUIC stream identifier.
/// </summary>
internal readonly struct QuicStreamId
{
    /// <summary>
    /// The bit that distinguishes client-initiated and server-initiated streams.
    /// </summary>
    private const ulong ClientInitiatedBitMask = 0x01;

    /// <summary>
    /// The bit that distinguishes bidirectional and unidirectional streams.
    /// </summary>
    private const ulong BidirectionalBitMask = 0x02;

    private readonly ulong value;

    internal QuicStreamId(ulong value)
    {
        this.value = value;
    }

    /// <summary>
    /// Gets the decoded stream identifier value.
    /// </summary>
    internal ulong Value => value;

    /// <summary>
    /// Gets the stream type classification derived from the low-order bits.
    /// </summary>
    internal QuicStreamType StreamType => IsBidirectional ? QuicStreamType.Bidirectional : QuicStreamType.Unidirectional;

    /// <summary>
    /// Gets whether the stream was initiated by a client.
    /// </summary>
    internal bool IsClientInitiated => (value & ClientInitiatedBitMask) == 0;

    /// <summary>
    /// Gets whether the stream was initiated by a server.
    /// </summary>
    internal bool IsServerInitiated => !IsClientInitiated;

    /// <summary>
    /// Gets whether the stream is bidirectional.
    /// </summary>
    internal bool IsBidirectional => (value & BidirectionalBitMask) == 0;

    /// <summary>
    /// Gets whether the stream is unidirectional.
    /// </summary>
    internal bool IsUnidirectional => !IsBidirectional;
}

