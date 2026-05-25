namespace Incursa.Quic.Http3;

/// <summary>
/// Represents an unknown or reserved HTTP/3 frame.
/// </summary>
public sealed class Http3UnknownFrame : Http3Frame
{
    /// <summary>
    /// Initializes a new instance of the <see cref="Http3UnknownFrame" /> class.
    /// </summary>
    public Http3UnknownFrame(ulong type, byte[] payload)
        : base(type, payload)
    {
    }
}
