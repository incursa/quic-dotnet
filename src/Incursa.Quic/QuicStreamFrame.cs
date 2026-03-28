namespace Incursa.Quic;

/// <summary>
/// A parsed STREAM frame view.
/// </summary>
public readonly ref struct QuicStreamFrame
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
    public byte FrameType => frameType;

    /// <summary>
    /// Gets the parsed stream identifier.
    /// </summary>
    public QuicStreamId StreamId => streamId;

    /// <summary>
    /// Gets the parsed stream type derived from the stream identifier.
    /// </summary>
    public QuicStreamType StreamType => streamId.StreamType;

    /// <summary>
    /// Gets whether the frame includes an Offset field.
    /// </summary>
    public bool HasOffset => hasOffset;

    /// <summary>
    /// Gets the offset, or zero when the field is absent.
    /// </summary>
    public ulong Offset => offset;

    /// <summary>
    /// Gets whether the frame includes a Length field.
    /// </summary>
    public bool HasLength => hasLength;

    /// <summary>
    /// Gets the parsed Stream Data length, or zero when the field is absent.
    /// </summary>
    public ulong Length => length;

    /// <summary>
    /// Gets whether the FIN bit is set.
    /// </summary>
    public bool IsFin => fin;

    /// <summary>
    /// Gets the Stream Data bytes.
    /// </summary>
    public ReadOnlySpan<byte> StreamData => streamData;

    /// <summary>
    /// Gets the number of Stream Data bytes in the parsed view.
    /// </summary>
    public int StreamDataLength => streamData.Length;

    /// <summary>
    /// Gets the total number of bytes consumed from the packet payload slice.
    /// </summary>
    public int ConsumedLength => consumedLength;
}
