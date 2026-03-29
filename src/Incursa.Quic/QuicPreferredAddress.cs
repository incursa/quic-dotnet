namespace Incursa.Quic;

/// <summary>
/// A parsed preferred_address transport parameter value.
/// </summary>
public sealed class QuicPreferredAddress
{
    /// <summary>
    /// Gets or sets the IPv4 address bytes.
    /// </summary>
    public byte[] IPv4Address { get; set; } = [];

    /// <summary>
    /// Gets or sets the IPv4 port.
    /// </summary>
    public ushort IPv4Port { get; set; }

    /// <summary>
    /// Gets or sets the IPv6 address bytes.
    /// </summary>
    public byte[] IPv6Address { get; set; } = [];

    /// <summary>
    /// Gets or sets the IPv6 port.
    /// </summary>
    public ushort IPv6Port { get; set; }

    /// <summary>
    /// Gets or sets the alternative connection ID bytes.
    /// </summary>
    public byte[] ConnectionId { get; set; } = [];

    /// <summary>
    /// Gets or sets the stateless reset token bytes.
    /// </summary>
    public byte[] StatelessResetToken { get; set; } = [];
}
