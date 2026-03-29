namespace Incursa.Quic;

/// <summary>
/// A parsed or constructed PATH_CHALLENGE frame.
/// </summary>
public readonly ref struct QuicPathChallengeFrame
{
    private readonly ReadOnlySpan<byte> data;

    /// <summary>
    /// Initializes a PATH_CHALLENGE frame view.
    /// </summary>
    public QuicPathChallengeFrame(ReadOnlySpan<byte> data)
    {
        this.data = data;
    }

    /// <summary>
    /// Gets the 8-byte challenge payload.
    /// </summary>
    public ReadOnlySpan<byte> Data => data;
}
