namespace Incursa.Quic.Http3;

/// <summary>
/// Represents an HTTP/3 PUSH_PROMISE frame.
/// </summary>
public sealed class Http3PushPromiseFrame : Http3Frame
{
    /// <summary>
    /// Initializes a new instance of the <see cref="Http3PushPromiseFrame" /> class.
    /// </summary>
    public Http3PushPromiseFrame(ulong pushId, byte[] encodedFieldSection, byte[] payload)
        : base((ulong)Http3FrameType.PushPromise, payload)
    {
        PushId = pushId;
        EncodedFieldSection = encodedFieldSection;
    }

    /// <summary>
    /// Gets the Push ID.
    /// </summary>
    public ulong PushId { get; }

    /// <summary>
    /// Gets the QPACK-encoded field section.
    /// </summary>
    public byte[] EncodedFieldSection { get; }
}
