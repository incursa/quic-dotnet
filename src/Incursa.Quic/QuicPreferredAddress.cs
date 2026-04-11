namespace Incursa.Quic;

/// <summary>
/// A parsed preferred_address transport parameter value.
/// </summary>
internal sealed class QuicPreferredAddress
{
    /// <summary>
    /// Gets or sets the IPv4 address bytes.
    /// </summary>
    internal byte[] IPv4Address { get; set; } = [];

    /// <summary>
    /// Gets or sets the IPv4 port.
    /// </summary>
    internal ushort IPv4Port { get; set; }

    /// <summary>
    /// Gets or sets the IPv6 address bytes.
    /// </summary>
    internal byte[] IPv6Address { get; set; } = [];

    /// <summary>
    /// Gets or sets the IPv6 port.
    /// </summary>
    internal ushort IPv6Port { get; set; }

    /// <summary>
    /// Gets or sets the alternative connection ID bytes.
    /// </summary>
    internal byte[] ConnectionId { get; set; } = [];

    /// <summary>
    /// Gets or sets the stateless reset token bytes.
    /// </summary>
    internal byte[] StatelessResetToken { get; set; } = [];
}

