namespace Incursa.Quic;

/// <summary>
/// Provides helpers for RFC 9000 idle-timeout behavior that can be expressed without a connection state machine.
/// </summary>
public sealed class QuicIdleTimeoutState
{
    private bool hasAckElicitingPacketBeenSentSinceLastPeerPacket;

    /// <summary>
    /// Initializes a new idle-timeout tracker for an effective timeout value.
    /// </summary>
    /// <param name="effectiveIdleTimeoutMicros">The effective idle timeout, in microseconds.</param>
    public QuicIdleTimeoutState(ulong effectiveIdleTimeoutMicros)
    {
        if (effectiveIdleTimeoutMicros == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(effectiveIdleTimeoutMicros));
        }

        EffectiveIdleTimeoutMicros = effectiveIdleTimeoutMicros;
        IdleTimerRestartAtMicros = 0;
        IdleTimeoutDeadlineMicros = effectiveIdleTimeoutMicros;
    }

    /// <summary>
    /// Gets the effective idle timeout, in microseconds.
    /// </summary>
    public ulong EffectiveIdleTimeoutMicros { get; }

    /// <summary>
    /// Gets the timestamp at which the idle timer was most recently restarted.
    /// </summary>
    public ulong IdleTimerRestartAtMicros { get; private set; }

    /// <summary>
    /// Gets the current idle-timeout deadline.
    /// </summary>
    public ulong IdleTimeoutDeadlineMicros { get; private set; }

    /// <summary>
    /// Gets whether an ack-eliciting packet has been sent since the most recent peer packet was processed.
    /// </summary>
    public bool HasAckElicitingPacketBeenSentSinceLastPeerPacket => hasAckElicitingPacketBeenSentSinceLastPeerPacket;

    /// <summary>
    /// Computes the effective idle timeout from both endpoints' transport parameters and the current PTO floor.
    /// </summary>
    /// <remarks>
    /// A zero or missing advertised timeout is treated as disabled. The returned timeout is floored to three times PTO.
    /// </remarks>
    public static bool TryComputeEffectiveIdleTimeoutMicros(
        ulong? localMaxIdleTimeoutMicros,
        ulong? peerMaxIdleTimeoutMicros,
        ulong currentProbeTimeoutMicros,
        out ulong effectiveIdleTimeoutMicros)
    {
        effectiveIdleTimeoutMicros = default;

        if (currentProbeTimeoutMicros == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(currentProbeTimeoutMicros));
        }

        if (!TrySelectAdvertisedIdleTimeoutMicros(localMaxIdleTimeoutMicros, peerMaxIdleTimeoutMicros, out ulong advertisedIdleTimeoutMicros))
        {
            return false;
        }

        ulong minimumEffectiveIdleTimeoutMicros = MultiplySaturating(currentProbeTimeoutMicros, 3);
        effectiveIdleTimeoutMicros = Math.Max(advertisedIdleTimeoutMicros, minimumEffectiveIdleTimeoutMicros);
        return true;
    }

    /// <summary>
    /// Records that a peer packet was processed successfully and restarts the idle timer.
    /// </summary>
    public void RecordPeerPacketProcessed(ulong receivedAtMicros)
    {
        IdleTimerRestartAtMicros = receivedAtMicros;
        IdleTimeoutDeadlineMicros = SaturatingAdd(receivedAtMicros, EffectiveIdleTimeoutMicros);
        hasAckElicitingPacketBeenSentSinceLastPeerPacket = false;
    }

    /// <summary>
    /// Records that an ack-eliciting packet was sent and restarts the idle timer on the first such packet
    /// after the last peer packet.
    /// </summary>
    public void RecordAckElicitingPacketSent(ulong sentAtMicros)
    {
        if (hasAckElicitingPacketBeenSentSinceLastPeerPacket)
        {
            return;
        }

        IdleTimerRestartAtMicros = sentAtMicros;
        IdleTimeoutDeadlineMicros = SaturatingAdd(sentAtMicros, EffectiveIdleTimeoutMicros);
        hasAckElicitingPacketBeenSentSinceLastPeerPacket = true;
    }

    /// <summary>
    /// Determines whether the idle deadline has passed.
    /// </summary>
    public bool HasTimedOut(ulong nowMicros)
    {
        return nowMicros > IdleTimeoutDeadlineMicros;
    }

    private static bool TrySelectAdvertisedIdleTimeoutMicros(
        ulong? localMaxIdleTimeoutMicros,
        ulong? peerMaxIdleTimeoutMicros,
        out ulong advertisedIdleTimeoutMicros)
    {
        advertisedIdleTimeoutMicros = default;

        bool localAdvertised = localMaxIdleTimeoutMicros is > 0;
        bool peerAdvertised = peerMaxIdleTimeoutMicros is > 0;

        if (!localAdvertised && !peerAdvertised)
        {
            return false;
        }

        if (localAdvertised && !peerAdvertised)
        {
            advertisedIdleTimeoutMicros = localMaxIdleTimeoutMicros!.Value;
            return true;
        }

        if (!localAdvertised && peerAdvertised)
        {
            advertisedIdleTimeoutMicros = peerMaxIdleTimeoutMicros!.Value;
            return true;
        }

        advertisedIdleTimeoutMicros = Math.Min(localMaxIdleTimeoutMicros!.Value, peerMaxIdleTimeoutMicros!.Value);
        return true;
    }

    private static ulong MultiplySaturating(ulong value, ulong multiplier)
    {
        if (value == 0 || multiplier == 0)
        {
            return 0;
        }

        if (value > ulong.MaxValue / multiplier)
        {
            return ulong.MaxValue;
        }

        return value * multiplier;
    }

    private static ulong SaturatingAdd(ulong left, ulong right)
    {
        if (ulong.MaxValue - left < right)
        {
            return ulong.MaxValue;
        }

        return left + right;
    }
}
