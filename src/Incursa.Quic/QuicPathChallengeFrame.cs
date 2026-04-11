namespace Incursa.Quic;

/// <summary>
/// A parsed or constructed PATH_CHALLENGE frame.
/// </summary>
internal readonly ref struct QuicPathChallengeFrame
{
    private readonly ReadOnlySpan<byte> data;

    /// <summary>
    /// Initializes a PATH_CHALLENGE frame view.
    /// </summary>
    internal QuicPathChallengeFrame(ReadOnlySpan<byte> data)
    {
        this.data = data;
    }

    /// <summary>
    /// Gets the 8-byte challenge payload.
    /// </summary>
    internal ReadOnlySpan<byte> Data => data;
}

