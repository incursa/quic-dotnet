namespace Incursa.Quic;

/// <summary>
/// Tracks the terminal connection lifecycle states that do not depend on stream scheduling.
/// </summary>
public sealed class QuicConnectionLifecycleState
{
    private bool isClosing;
    private bool isDraining;

    /// <summary>
    /// Initializes a new connection lifecycle state tracker.
    /// </summary>
    public QuicConnectionLifecycleState()
    {
    }

    /// <summary>
    /// Gets whether the connection is in the closing state.
    /// </summary>
    public bool IsClosing => isClosing;

    /// <summary>
    /// Gets whether the connection is in the draining state.
    /// </summary>
    public bool IsDraining => isDraining;

    /// <summary>
    /// Gets whether the connection can still send ordinary packets.
    /// </summary>
    public bool CanSendPackets => !isClosing && !isDraining;

    /// <summary>
    /// Attempts to enter the closing state.
    /// </summary>
    public bool TryEnterClosingState()
    {
        if (isClosing || isDraining)
        {
            return false;
        }

        isClosing = true;
        return true;
    }

    /// <summary>
    /// Attempts to enter the draining state.
    /// </summary>
    public bool TryEnterDrainingState()
    {
        if (isDraining)
        {
            return false;
        }

        isClosing = false;
        isDraining = true;
        return true;
    }

    /// <summary>
    /// Detects a potential Stateless Reset and enters the draining state when the trailing token matches.
    /// </summary>
    public bool TryHandlePotentialStatelessReset(ReadOnlySpan<byte> datagram, ReadOnlySpan<byte> candidateTokens)
    {
        if (isDraining
            || !QuicStatelessReset.IsPotentialStatelessReset(datagram)
            || !QuicStatelessReset.MatchesAnyStatelessResetToken(datagram, candidateTokens))
        {
            return false;
        }

        return TryEnterDrainingState();
    }
}
