namespace Incursa.Quic.Http3;

/// <summary>
/// Represents an HTTP/3 DATA frame.
/// </summary>
public sealed class Http3DataFrame : Http3Frame
{
    /// <summary>
    /// Initializes a new instance of the <see cref="Http3DataFrame" /> class.
    /// </summary>
    public Http3DataFrame(byte[] data)
        : base((ulong)Http3FrameType.Data, data)
    {
    }

    /// <summary>
    /// Gets the DATA payload.
    /// </summary>
    public ReadOnlyMemory<byte> Data => Payload;
}
