namespace Incursa.Quic;

/// <summary>
/// Tracks the peer's advertised connection IDs and the latest destination connection ID accepted
/// for packet routing.
/// </summary>
internal sealed class QuicConnectionPeerConnectionIdState
{
    internal const ulong DefaultActiveConnectionIdLimit = 2;

    // Sequence-indexed peer records, keyed by the peer's NEW_CONNECTION_ID frame sequence number.
    private readonly Dictionary<ulong, QuicConnectionPeerConnectionIdRecord> connectionIdsBySequence = [];
    // Historical sequence records keep duplicate/conflict checks intact after an ID leaves the active set.
    private readonly Dictionary<ulong, QuicConnectionPeerConnectionIdRecord> connectionIdHistoryBySequence = [];
    // Reverse lookup used to reject the same connection ID being reused under a different sequence number,
    // including values that were later retired from the active set.
    private readonly Dictionary<QuicConnectionIdKey, ulong> sequenceByConnectionId = [];
    private readonly HashSet<ulong> retiredSequenceNumbersReportedToRuntime = [];
    // The active destination connection ID is copied so the runtime can hand out a stable span.
    private byte[] currentDestinationConnectionId = [];
    private ulong? currentDestinationConnectionIdSequence;
    private ulong retirePriorTo;

    /// <summary>
    /// Gets the current destination connection ID chosen from the highest accepted sequence number.
    /// </summary>
    internal ReadOnlyMemory<byte> CurrentDestinationConnectionId => currentDestinationConnectionId;

    /// <summary>
    /// Gets the sequence number associated with <see cref="CurrentDestinationConnectionId" />, if any.
    /// </summary>
    internal ulong? CurrentDestinationConnectionIdSequence => currentDestinationConnectionIdSequence;

    /// <summary>
    /// Gets the number of active peer-issued connection IDs tracked for outbound packet selection.
    /// </summary>
    internal int ActiveConnectionIdCount => connectionIdsBySequence.Count;

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
        return TryAcceptNewConnectionId(
            frame,
            requiresZeroLengthDestinationConnectionId,
            DefaultActiveConnectionIdLimit,
            ReadOnlySpan<byte>.Empty,
            out errorCode,
            out destinationConnectionIdChanged,
            out _);
    }

    /// <summary>
    /// Accepts a peer-issued NEW_CONNECTION_ID frame when it is consistent with previously seen state.
    /// </summary>
    /// <param name="frame">The frame to record.</param>
    /// <param name="requiresZeroLengthDestinationConnectionId">Whether the connection is operating in zero-length DCID mode.</param>
    /// <param name="activeConnectionIdLimit">The local active_connection_id_limit advertised to the peer.</param>
    /// <param name="initialDestinationConnectionId">The initial peer connection ID, which has implicit sequence number 0.</param>
    /// <param name="errorCode">Receives the transport error code when the frame is rejected.</param>
    /// <param name="destinationConnectionIdChanged">Receives <see langword="true" /> when the active destination connection ID advances.</param>
    /// <param name="retiredSequenceNumbers">Receives peer-issued sequence numbers that must be retired.</param>
    /// <returns><see langword="true" /> when the frame is accepted; otherwise, <see langword="false" />.</returns>
    internal bool TryAcceptNewConnectionId(
        QuicNewConnectionIdFrame frame,
        bool requiresZeroLengthDestinationConnectionId,
        ulong activeConnectionIdLimit,
        ReadOnlySpan<byte> initialDestinationConnectionId,
        out QuicTransportErrorCode errorCode,
        out bool destinationConnectionIdChanged,
        out ulong[] retiredSequenceNumbers)
    {
        errorCode = QuicTransportErrorCode.NoError;
        destinationConnectionIdChanged = false;
        retiredSequenceNumbers = [];

        if (requiresZeroLengthDestinationConnectionId)
        {
            errorCode = QuicTransportErrorCode.ProtocolViolation;
            return false;
        }

        if (frame.RetirePriorTo > frame.SequenceNumber)
        {
            errorCode = QuicTransportErrorCode.ProtocolViolation;
            return false;
        }

        if (!TryEnsureInitialDestinationConnectionId(initialDestinationConnectionId, out errorCode))
        {
            return false;
        }

        if (!QuicConnectionIdKey.TryCreate(frame.ConnectionId, out QuicConnectionIdKey connectionIdKey))
        {
            errorCode = QuicTransportErrorCode.ProtocolViolation;
            return false;
        }

        QuicConnectionPeerConnectionIdRecord record = new(
            connectionIdKey,
            frame.ConnectionId.ToArray(),
            frame.RetirePriorTo,
            frame.StatelessResetToken.ToArray());

        if (connectionIdHistoryBySequence.TryGetValue(frame.SequenceNumber, out QuicConnectionPeerConnectionIdRecord existingRecord))
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

        if (frame.SequenceNumber < retirePriorTo)
        {
            connectionIdHistoryBySequence.Add(frame.SequenceNumber, record);
            sequenceByConnectionId.Add(connectionIdKey, frame.SequenceNumber);
            if (retiredSequenceNumbersReportedToRuntime.Add(frame.SequenceNumber))
            {
                retiredSequenceNumbers = [frame.SequenceNumber];
            }

            return true;
        }

        ulong effectiveRetirePriorTo = Math.Max(retirePriorTo, frame.RetirePriorTo);
        List<ulong> sequencesToRetire = [];
        foreach (ulong sequenceNumber in connectionIdsBySequence.Keys)
        {
            if (sequenceNumber < effectiveRetirePriorTo)
            {
                sequencesToRetire.Add(sequenceNumber);
            }
        }

        ulong activeCountAfterProcessing = (ulong)(connectionIdsBySequence.Count - sequencesToRetire.Count + 1);
        if (activeCountAfterProcessing > activeConnectionIdLimit)
        {
            errorCode = QuicTransportErrorCode.ConnectionIdLimitError;
            return false;
        }

        ulong? previousDestinationSequence = currentDestinationConnectionIdSequence;
        byte[] previousDestinationConnectionId = currentDestinationConnectionId;

        foreach (ulong sequenceNumber in sequencesToRetire)
        {
            connectionIdsBySequence.Remove(sequenceNumber);
            retiredSequenceNumbersReportedToRuntime.Add(sequenceNumber);
        }

        retirePriorTo = effectiveRetirePriorTo;
        connectionIdsBySequence.Add(frame.SequenceNumber, record);
        connectionIdHistoryBySequence.Add(frame.SequenceNumber, record);
        sequenceByConnectionId.Add(connectionIdKey, frame.SequenceNumber);

        RecomputeCurrentDestinationConnectionId();
        retiredSequenceNumbers = sequencesToRetire.ToArray();
        destinationConnectionIdChanged =
            previousDestinationSequence != currentDestinationConnectionIdSequence
            || !previousDestinationConnectionId.AsSpan().SequenceEqual(currentDestinationConnectionId);

        return true;
    }

    /// <summary>
    /// Clears all peer connection ID state.
    /// </summary>
    internal void Clear()
    {
        connectionIdsBySequence.Clear();
        connectionIdHistoryBySequence.Clear();
        sequenceByConnectionId.Clear();
        retiredSequenceNumbersReportedToRuntime.Clear();
        currentDestinationConnectionId = [];
        currentDestinationConnectionIdSequence = null;
        retirePriorTo = 0;
    }

    private bool TryEnsureInitialDestinationConnectionId(
        ReadOnlySpan<byte> initialDestinationConnectionId,
        out QuicTransportErrorCode errorCode)
    {
        errorCode = QuicTransportErrorCode.NoError;

        if (initialDestinationConnectionId.IsEmpty
            || retirePriorTo > 0
            || connectionIdsBySequence.ContainsKey(0))
        {
            return true;
        }

        if (!QuicConnectionIdKey.TryCreate(initialDestinationConnectionId, out QuicConnectionIdKey connectionIdKey))
        {
            errorCode = QuicTransportErrorCode.ProtocolViolation;
            return false;
        }

        if (sequenceByConnectionId.TryGetValue(connectionIdKey, out ulong existingSequence)
            && existingSequence != 0)
        {
            errorCode = QuicTransportErrorCode.ProtocolViolation;
            return false;
        }

        QuicConnectionPeerConnectionIdRecord record = new(
            connectionIdKey,
            initialDestinationConnectionId.ToArray(),
            RetirePriorTo: 0,
            StatelessResetToken: []);
        connectionIdsBySequence.Add(0, record);
        connectionIdHistoryBySequence.Add(0, record);
        sequenceByConnectionId[connectionIdKey] = 0;
        RecomputeCurrentDestinationConnectionId();
        return true;
    }

    private void RecomputeCurrentDestinationConnectionId()
    {
        if (connectionIdsBySequence.Count == 0)
        {
            currentDestinationConnectionId = [];
            currentDestinationConnectionIdSequence = null;
            return;
        }

        ulong selectedSequence = 0;
        QuicConnectionPeerConnectionIdRecord selectedRecord = default;
        bool selected = false;
        foreach (KeyValuePair<ulong, QuicConnectionPeerConnectionIdRecord> entry in connectionIdsBySequence)
        {
            if (!selected || entry.Key > selectedSequence)
            {
                selectedSequence = entry.Key;
                selectedRecord = entry.Value;
                selected = true;
            }
        }

        currentDestinationConnectionIdSequence = selectedSequence;
        currentDestinationConnectionId = selectedRecord.ConnectionIdBytes.ToArray();
    }

    /// <summary>
    /// Stores the peer's connection ID material for a single sequence number.
    /// </summary>
    /// <param name="ConnectionId">The parsed connection ID value.</param>
    /// <param name="ConnectionIdBytes">The connection ID bytes copied from the NEW_CONNECTION_ID payload.</param>
    /// <param name="RetirePriorTo">The retire-prior-to threshold from the frame.</param>
    /// <param name="StatelessResetToken">The peer's stateless reset token copied for later comparison.</param>
    private readonly record struct QuicConnectionPeerConnectionIdRecord(
        QuicConnectionIdKey ConnectionId,
        byte[] ConnectionIdBytes,
        ulong RetirePriorTo,
        byte[] StatelessResetToken);
}
