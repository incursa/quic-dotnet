namespace Incursa.Quic;

/// <summary>
/// Describes the paired confidentiality and integrity packet-use limits for a QUIC AEAD selection.
/// </summary>
public readonly struct QuicAeadUsageLimits
{
    /// <summary>
    /// Initializes a new instance of the <see cref="QuicAeadUsageLimits"/> struct.
    /// </summary>
    /// <param name="confidentialityLimitPackets">The maximum packets that may be protected before rekeying.</param>
    /// <param name="integrityLimitPackets">The maximum packets that may be opened before rekeying.</param>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when either limit is not positive.</exception>
    public QuicAeadUsageLimits(double confidentialityLimitPackets, double integrityLimitPackets)
    {
        if (confidentialityLimitPackets <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(confidentialityLimitPackets));
        }

        if (integrityLimitPackets <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(integrityLimitPackets));
        }

        ConfidentialityLimitPackets = confidentialityLimitPackets;
        IntegrityLimitPackets = integrityLimitPackets;
    }

    /// <summary>
    /// Gets the confidentiality packet-use limit.
    /// </summary>
    public double ConfidentialityLimitPackets { get; }

    /// <summary>
    /// Gets the integrity packet-use limit.
    /// </summary>
    public double IntegrityLimitPackets { get; }
}
