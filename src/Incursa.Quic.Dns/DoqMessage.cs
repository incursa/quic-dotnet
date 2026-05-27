namespace Incursa.Quic.Dns;

/// <summary>
/// Represents one DNS message payload carried by DNS over QUIC framing.
/// </summary>
public readonly struct DoqMessage
{
    /// <summary>
    /// Initializes a new instance of the <see cref="DoqMessage"/> struct.
    /// </summary>
    public DoqMessage(ReadOnlyMemory<byte> payload)
    {
        Payload = payload;
    }

    /// <summary>
    /// Gets the DNS message payload without the DoQ length prefix.
    /// </summary>
    public ReadOnlyMemory<byte> Payload { get; }
}
