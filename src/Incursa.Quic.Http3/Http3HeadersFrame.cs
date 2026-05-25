namespace Incursa.Quic.Http3;

/// <summary>
/// Represents an HTTP/3 HEADERS frame.
/// </summary>
public sealed class Http3HeadersFrame : Http3Frame
{
    /// <summary>
    /// Initializes a new instance of the <see cref="Http3HeadersFrame" /> class.
    /// </summary>
    public Http3HeadersFrame(byte[] encodedFieldSection)
        : base((ulong)Http3FrameType.Headers, encodedFieldSection)
    {
    }

    /// <summary>
    /// Gets the QPACK-encoded field section.
    /// </summary>
    public ReadOnlyMemory<byte> EncodedFieldSection => Payload;
}
