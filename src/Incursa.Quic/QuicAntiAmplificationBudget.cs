namespace Incursa.Quic;

/// <summary>
/// Tracks the RFC 9000 anti-amplification budget for an unvalidated peer address.
/// </summary>
internal sealed class QuicAntiAmplificationBudget
{
    /// <summary>
    /// RFC 9000 allows a server to send at most three times the bytes it has received before validation.
    /// </summary>
    private const ulong AmplificationFactor = 3;
    private ulong receivedPayloadBytes;
    private ulong sentPayloadBytes;

    /// <summary>
    /// Gets the total payload bytes received in datagrams uniquely attributable to a single connection.
    /// </summary>
    internal ulong ReceivedPayloadBytes => receivedPayloadBytes;

    /// <summary>
    /// Gets the total payload bytes sent while this budget has been in force.
    /// </summary>
    internal ulong SentPayloadBytes => sentPayloadBytes;

    /// <summary>
    /// Gets whether the peer address has been validated.
    /// </summary>
    internal bool IsAddressValidated { get; private set; }

    /// <summary>
    /// Gets the remaining bytes that may be sent before the amplification limit is reached.
    /// </summary>
    internal ulong RemainingSendBudget => IsAddressValidated
        ? ulong.MaxValue
        : GetRemainingSendBudget();

    /// <summary>
    /// Marks the peer address as validated, which removes the amplification cap.
    /// </summary>
    internal void MarkAddressValidated()
    {
        IsAddressValidated = true;
    }

    /// <summary>
    /// Registers payload bytes received from a datagram.
    /// </summary>
    /// <remarks>
    /// Only payload bytes from datagrams uniquely attributable to a single connection are counted.
    /// </remarks>
    internal bool TryRegisterReceivedDatagramPayloadBytes(int payloadBytes, bool uniquelyAttributedToSingleConnection)
    {
        if (payloadBytes < 0)
        {
            return false;
        }

        if (uniquelyAttributedToSingleConnection)
        {
            receivedPayloadBytes = SaturatingAdd(receivedPayloadBytes, (ulong)payloadBytes);
        }

        return true;
    }

    /// <summary>
    /// Determines whether the requested payload bytes may be sent without exceeding the amplification limit.
    /// </summary>
    internal bool CanSend(int payloadBytes)
    {
        if (payloadBytes < 0)
        {
            return false;
        }

        return IsAddressValidated || (ulong)payloadBytes <= RemainingSendBudget;
    }

    /// <summary>
    /// Consumes send budget for the requested payload bytes.
    /// </summary>
    internal bool TryConsumeSendBudget(int payloadBytes)
    {
        if (!CanSend(payloadBytes))
        {
            return false;
        }

        sentPayloadBytes = SaturatingAdd(sentPayloadBytes, (ulong)payloadBytes);
        return true;
    }

    private ulong GetRemainingSendBudget()
    {
        ulong maximumAllowedBytes = SaturatingMultiply(receivedPayloadBytes, AmplificationFactor);
        return sentPayloadBytes >= maximumAllowedBytes ? 0 : maximumAllowedBytes - sentPayloadBytes;
    }

    private static ulong SaturatingAdd(ulong left, ulong right)
    {
        ulong result = left + right;
        return result < left ? ulong.MaxValue : result;
    }

    private static ulong SaturatingMultiply(ulong value, ulong multiplier)
    {
        if (value > ulong.MaxValue / multiplier)
        {
            return ulong.MaxValue;
        }

        return value * multiplier;
    }
}

