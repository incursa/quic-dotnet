namespace Incursa.Quic;

/// <summary>
/// Describes the paired confidentiality and integrity packet-use limits for a QUIC AEAD selection.
/// </summary>
internal readonly struct QuicAeadUsageLimits
{
    /// <summary>
    /// Initializes a new instance of the <see cref="QuicAeadUsageLimits"/> struct.
    /// </summary>
    /// <param name="confidentialityLimitPackets">The maximum packets that may be protected before rekeying.</param>
    /// <param name="integrityLimitPackets">The maximum packets that may be opened before rekeying.</param>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when either limit is not positive.</exception>
    internal QuicAeadUsageLimits(double confidentialityLimitPackets, double integrityLimitPackets)
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
    internal double ConfidentialityLimitPackets { get; }

    /// <summary>
    /// Gets the integrity packet-use limit.
    /// </summary>
    internal double IntegrityLimitPackets { get; }
}

/// <summary>
/// Tracks the lifecycle and availability state for a key set.
/// </summary>
internal enum QuicAeadKeyUsageState
{
    /// <summary>
    /// Key material has been configured but is not yet available for use.
    /// </summary>
    Pending,

    /// <summary>
    /// Key material is available and can be used.
    /// </summary>
    Available,

    /// <summary>
    /// Key material must no longer be used.
    /// </summary>
    Discarded,
}

/// <summary>
/// Tracks key availability against appendix B usage limits and supports transition/rejection checks.
/// </summary>
internal sealed class QuicAeadKeyLifecycle
{
    private readonly QuicAeadUsageLimits limits;
    private double protectedPackets;
    private double openedPackets;
    private bool zeroRttRejected;

    /// <summary>
    /// Initializes a new instance of the <see cref="QuicAeadKeyLifecycle"/> class.
    /// </summary>
    internal QuicAeadKeyLifecycle(QuicAeadUsageLimits limits)
    {
        this.limits = limits;
    }

    /// <summary>
    /// Gets the current lifecycle state of the key material.
    /// </summary>
    internal QuicAeadKeyUsageState State { get; private set; }

    /// <summary>
    /// Gets whether keys are available for immediate packet protection/decryption.
    /// </summary>
    internal bool IsAvailable => State == QuicAeadKeyUsageState.Available && !zeroRttRejected;

    /// <summary>
    /// Gets whether protection keys can be used for an additional packet.
    /// </summary>
    internal bool CanProtect => IsAvailable && protectedPackets < limits.ConfidentialityLimitPackets;

    /// <summary>
    /// Gets whether decryption keys can be used for an additional packet.
    /// </summary>
    internal bool CanOpen => IsAvailable && openedPackets < limits.IntegrityLimitPackets;

    /// <summary>
    /// Gets whether key material has been discarded.
    /// </summary>
    internal bool IsDiscarded => State == QuicAeadKeyUsageState.Discarded;

    /// <summary>
    /// Gets whether 0-RTT has been explicitly rejected for this key set.
    /// </summary>
    internal bool IsZeroRttRejected => zeroRttRejected;

    /// <summary>
    /// Gets the number of packets protected so far using this key set.
    /// </summary>
    internal double ProtectedPacketCount => protectedPackets;

    /// <summary>
    /// Gets the number of packets opened so far using this key set.
    /// </summary>
    internal double OpenedPacketCount => openedPackets;

    /// <summary>
    /// Marks key material available for use.
    /// </summary>
    internal bool TryActivate()
    {
        if (State != QuicAeadKeyUsageState.Pending || zeroRttRejected)
        {
            return false;
        }

        State = QuicAeadKeyUsageState.Available;
        return true;
    }

    /// <summary>
    /// Discards key material due to usage limit exhaustion or transition policy.
    /// </summary>
    internal void Discard()
    {
        State = QuicAeadKeyUsageState.Discarded;
    }

    /// <summary>
    /// Discards key material when 0-RTT is rejected.
    /// </summary>
    internal bool RejectZeroRtt()
    {
        if (zeroRttRejected)
        {
            return false;
        }

        zeroRttRejected = true;
        Discard();
        return true;
    }

    /// <summary>
    /// Records one protected packet when limits allow.
    /// </summary>
    internal bool TryUseForProtection()
    {
        if (!CanProtect)
        {
            return false;
        }

        protectedPackets += 1;
        if (!CanProtect || !CanOpen)
        {
            State = QuicAeadKeyUsageState.Discarded;
        }

        return true;
    }

    /// <summary>
    /// Records one opened packet when limits allow.
    /// </summary>
    internal bool TryUseForOpening()
    {
        if (!CanOpen)
        {
            return false;
        }

        openedPackets += 1;
        if (!CanProtect || !CanOpen)
        {
            State = QuicAeadKeyUsageState.Discarded;
        }

        return true;
    }
}

