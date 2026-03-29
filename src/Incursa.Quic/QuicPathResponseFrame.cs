namespace Incursa.Quic;

/// <summary>
/// A parsed or constructed PATH_RESPONSE frame.
/// </summary>
public readonly ref struct QuicPathResponseFrame
{
    private readonly ReadOnlySpan<byte> data;

    /// <summary>
    /// Initializes a PATH_RESPONSE frame view.
    /// </summary>
    public QuicPathResponseFrame(ReadOnlySpan<byte> data)
    {
        this.data = data;
    }

    /// <summary>
    /// Gets the 8-byte response payload.
    /// </summary>
    public ReadOnlySpan<byte> Data => data;
}
