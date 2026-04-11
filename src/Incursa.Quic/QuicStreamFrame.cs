namespace Incursa.Quic;

/// <summary>
/// A parsed STREAM frame view.
/// </summary>
internal readonly ref struct QuicStreamFrame
{
    private readonly byte frameType;
    private readonly QuicStreamId streamId;
    private readonly bool hasOffset;
    private readonly ulong offset;
    private readonly bool hasLength;
    private readonly ulong length;
    private readonly bool fin;
    private readonly ReadOnlySpan<byte> streamData;
    private readonly int consumedLength;

    internal QuicStreamFrame(
        byte frameType,
        QuicStreamId streamId,
        bool hasOffset,
        ulong offset,
        bool hasLength,
        ulong length,
        bool fin,
        ReadOnlySpan<byte> streamData,
        int consumedLength)
    {
        this.frameType = frameType;
        this.streamId = streamId;
        this.hasOffset = hasOffset;
        this.offset = offset;
        this.hasLength = hasLength;
        this.length = length;
        this.fin = fin;
        this.streamData = streamData;
        this.consumedLength = consumedLength;
    }

    /// <summary>
    /// Gets the STREAM frame type byte.
    /// </summary>
    internal byte FrameType => frameType;

    /// <summary>
    /// Gets the parsed stream identifier.
    /// </summary>
    internal QuicStreamId StreamId => streamId;

    /// <summary>
    /// Gets the parsed stream type derived from the stream identifier.
    /// </summary>
    internal QuicStreamType StreamType => streamId.StreamType;

    /// <summary>
    /// Gets whether the frame includes an Offset field.
    /// </summary>
    internal bool HasOffset => hasOffset;

    /// <summary>
    /// Gets the offset, or zero when the field is absent.
    /// </summary>
    internal ulong Offset => offset;

    /// <summary>
    /// Gets whether the frame includes a Length field.
    /// </summary>
    internal bool HasLength => hasLength;

    /// <summary>
    /// Gets the parsed Stream Data length, or zero when the field is absent.
    /// </summary>
    internal ulong Length => length;

    /// <summary>
    /// Gets whether the FIN bit is set.
    /// </summary>
    internal bool IsFin => fin;

    /// <summary>
    /// Gets the Stream Data bytes.
    /// </summary>
    internal ReadOnlySpan<byte> StreamData => streamData;

    /// <summary>
    /// Gets the number of Stream Data bytes in the parsed view.
    /// </summary>
    internal int StreamDataLength => streamData.Length;

    /// <summary>
    /// Gets the total number of bytes consumed from the packet payload slice.
    /// </summary>
    internal int ConsumedLength => consumedLength;
}

