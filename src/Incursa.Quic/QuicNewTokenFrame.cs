namespace Incursa.Quic;

/// <summary>
/// A parsed or constructed NEW_TOKEN frame.
/// </summary>
internal readonly ref struct QuicNewTokenFrame
{
    private readonly ReadOnlySpan<byte> token;

    /// <summary>
    /// Initializes a NEW_TOKEN frame view.
    /// </summary>
    internal QuicNewTokenFrame(ReadOnlySpan<byte> token)
    {
        this.token = token;
    }

    /// <summary>
    /// Gets the token bytes.
    /// </summary>
    internal ReadOnlySpan<byte> Token => token;
}

