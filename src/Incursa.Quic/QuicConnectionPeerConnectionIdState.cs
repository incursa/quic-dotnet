namespace Incursa.Quic;

/// <summary>
/// Tracks the peer's advertised connection IDs and the latest destination connection ID accepted
/// for packet routing.
/// </summary>
internal sealed class QuicConnectionPeerConnectionIdState
{
    // Sequence-indexed peer records, keyed by the peer's NEW_CONNECTION_ID frame sequence number.
    private readonly Dictionary<ulong, QuicConnectionPeerConnectionIdRecord> connectionIdsBySequence = [];
    // Reverse lookup used to reject the same connection ID being reused under a different sequence number.
    private readonly Dictionary<QuicConnectionIdKey, ulong> sequenceByConnectionId = [];
    // The active destination connection ID is copied so the runtime can hand out a stable span.
    private byte[] currentDestinationConnectionId = [];
    private ulong? currentDestinationConnectionIdSequence;

    /// <summary>
    /// Gets the current destination connection ID chosen from the highest accepted sequence number.
    /// </summary>
    internal ReadOnlyMemory<byte> CurrentDestinationConnectionId => currentDestinationConnectionId;

    /// <summary>
    /// Gets the sequence number associated with <see cref="CurrentDestinationConnectionId" />, if any.
    /// </summary>
    internal ulong? CurrentDestinationConnectionIdSequence => currentDestinationConnectionIdSequence;

    /// <summary>
    /// Accepts a peer-issued NEW_CONNECTION_ID frame when it is consistent with previously seen state.
    /// </summary>
    /// <param name="frame">The frame to record.</param>
    /// <param name="requiresZeroLengthDestinationConnectionId">Whether the connection is operating in zero-length DCID mode.</param>
    /// <param name="errorCode">Receives the transport error code when the frame is rejected.</param>
    /// <param name="destinationConnectionIdChanged">Receives <see langword="true" /> when the active destination connection ID advances.</param>
    /// <returns><see langword="true" /> when the frame is accepted; otherwise, <see langword="false" />.</returns>
    internal bool TryAcceptNewConnectionId(
        QuicNewConnectionIdFrame frame,
        bool requiresZeroLengthDestinationConnectionId,
        out QuicTransportErrorCode errorCode,
        out bool destinationConnectionIdChanged)
    {
        errorCode = QuicTransportErrorCode.NoError;
        destinationConnectionIdChanged = false;

        if (requiresZeroLengthDestinationConnectionId)
        {
            errorCode = QuicTransportErrorCode.ProtocolViolation;
            return false;
        }

        if (!QuicConnectionIdKey.TryCreate(frame.ConnectionId, out QuicConnectionIdKey connectionIdKey))
        {
            errorCode = QuicTransportErrorCode.ProtocolViolation;
            return false;
        }

        if (connectionIdsBySequence.TryGetValue(frame.SequenceNumber, out QuicConnectionPeerConnectionIdRecord existingRecord))
        {
            if (existingRecord.ConnectionId != connectionIdKey
                || existingRecord.RetirePriorTo != frame.RetirePriorTo
                || !existingRecord.StatelessResetToken.AsSpan().SequenceEqual(frame.StatelessResetToken))
            {
                errorCode = QuicTransportErrorCode.ProtocolViolation;
                return false;
            }

            return true;
        }

        if (sequenceByConnectionId.TryGetValue(connectionIdKey, out ulong existingSequence)
            && existingSequence != frame.SequenceNumber)
        {
            errorCode = QuicTransportErrorCode.ProtocolViolation;
            return false;
        }

        byte[] statelessResetToken = frame.StatelessResetToken.ToArray();
        QuicConnectionPeerConnectionIdRecord record = new(connectionIdKey, frame.RetirePriorTo, statelessResetToken);
        connectionIdsBySequence.Add(frame.SequenceNumber, record);
        sequenceByConnectionId.Add(connectionIdKey, frame.SequenceNumber);

        if (!currentDestinationConnectionIdSequence.HasValue
            || frame.SequenceNumber > currentDestinationConnectionIdSequence.Value)
        {
            currentDestinationConnectionIdSequence = frame.SequenceNumber;
            currentDestinationConnectionId = frame.ConnectionId.ToArray();
            destinationConnectionIdChanged = true;
        }

        return true;
    }

    /// <summary>
    /// Clears all peer connection ID state.
    /// </summary>
    internal void Clear()
    {
        connectionIdsBySequence.Clear();
        sequenceByConnectionId.Clear();
        currentDestinationConnectionId = [];
        currentDestinationConnectionIdSequence = null;
    }

    /// <summary>
    /// Stores the peer's connection ID material for a single sequence number.
    /// </summary>
    /// <param name="ConnectionId">The parsed connection ID value.</param>
    /// <param name="RetirePriorTo">The retire-prior-to threshold from the frame.</param>
    /// <param name="StatelessResetToken">The peer's stateless reset token copied for later comparison.</param>
    private readonly record struct QuicConnectionPeerConnectionIdRecord(
        QuicConnectionIdKey ConnectionId,
        ulong RetirePriorTo,
        byte[] StatelessResetToken);
}
