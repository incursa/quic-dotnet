// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

/// <summary>
/// Tracks the peer's advertised connection IDs and the destination connection ID selected for
/// outbound packets.
/// </summary>
internal sealed class QuicConnectionPeerConnectionIdState
{
    internal const ulong DefaultActiveConnectionIdLimit = 2;
    private const ulong PendingRetiredConnectionIdLimitMultiplier = 2;

    // Sequence-indexed peer records, keyed by the peer's NEW_CONNECTION_ID frame sequence number.
    private readonly Dictionary<ulong, QuicConnectionPeerConnectionIdRecord> connectionIdsBySequence = [];
    // Historical sequence records keep duplicate/conflict checks intact after an ID leaves the active set.
    private readonly Dictionary<ulong, QuicConnectionPeerConnectionIdRecord> connectionIdHistoryBySequence = [];
    // Reverse lookup used to reject the same connection ID being reused under a different sequence number,
    // including values that were later retired from the active set.
    private readonly Dictionary<QuicConnectionIdKey, ulong> sequenceByConnectionId = [];
    // Records the local/destination address pair on which each peer-issued CID has been used.
    private readonly Dictionary<ulong, QuicConnectionPathIdentity> pathBySequence = [];
    private readonly HashSet<ulong> retiredSequenceNumbersReportedToRuntime = [];
    // The active destination connection ID is copied so the runtime can hand out a stable span.
    private byte[] currentDestinationConnectionId = [];
    private ulong? currentDestinationConnectionIdSequence;
    private ulong retirePriorTo;

    private const ulong PreferredAddressConnectionIdSequence = 1;

    /// <summary>
    /// Gets the current destination connection ID selected for outbound packets.
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
    /// Gets the number of locally retired peer-issued connection IDs still tracked for retirement reporting.
    /// </summary>
    internal int PendingRetiredConnectionIdCount => retiredSequenceNumbersReportedToRuntime.Count;

    internal static ulong GetPendingRetiredConnectionIdLimit(ulong activeConnectionIdLimit)
    {
        return activeConnectionIdLimit > ulong.MaxValue / PendingRetiredConnectionIdLimitMultiplier
            ? ulong.MaxValue
            : activeConnectionIdLimit * PendingRetiredConnectionIdLimitMultiplier;
    }

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
            if (!CanReportRetiredSequenceNumbers(
                    [frame.SequenceNumber],
                    activeConnectionIdLimit,
                    out errorCode))
            {
                return false;
            }

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

        if (!CanReportRetiredSequenceNumbers(
                sequencesToRetire,
                activeConnectionIdLimit,
                out errorCode))
        {
            return false;
        }

        ulong? previousDestinationSequence = currentDestinationConnectionIdSequence;
        byte[] previousDestinationConnectionId = currentDestinationConnectionId;

        foreach (ulong sequenceNumber in sequencesToRetire)
        {
            connectionIdsBySequence.Remove(sequenceNumber);
            pathBySequence.Remove(sequenceNumber);
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

    internal bool TryAcceptPreferredAddressConnectionId(
        QuicPreferredAddress preferredAddress,
        ulong activeConnectionIdLimit,
        ReadOnlySpan<byte> initialDestinationConnectionId,
        out QuicTransportErrorCode errorCode,
        out bool destinationConnectionIdChanged)
    {
        errorCode = QuicTransportErrorCode.NoError;
        destinationConnectionIdChanged = false;

        if (!TryEnsureInitialDestinationConnectionId(initialDestinationConnectionId, out errorCode))
        {
            return false;
        }

        if (preferredAddress.ConnectionId.Length is 0 or > QuicConnectionIdKey.MaximumLength
            || preferredAddress.StatelessResetToken.Length != QuicStatelessReset.StatelessResetTokenLength
            || !QuicConnectionIdKey.TryCreate(preferredAddress.ConnectionId, out QuicConnectionIdKey connectionIdKey))
        {
            errorCode = QuicTransportErrorCode.TransportParameterError;
            return false;
        }

        QuicConnectionPeerConnectionIdRecord record = new(
            connectionIdKey,
            preferredAddress.ConnectionId.ToArray(),
            RetirePriorTo: 0,
            preferredAddress.StatelessResetToken.ToArray());

        if (connectionIdHistoryBySequence.TryGetValue(PreferredAddressConnectionIdSequence, out QuicConnectionPeerConnectionIdRecord existingRecord))
        {
            if (existingRecord.ConnectionId != connectionIdKey
                || existingRecord.RetirePriorTo != 0
                || !existingRecord.StatelessResetToken.AsSpan().SequenceEqual(preferredAddress.StatelessResetToken))
            {
                errorCode = QuicTransportErrorCode.TransportParameterError;
                return false;
            }

            return true;
        }

        if (sequenceByConnectionId.TryGetValue(connectionIdKey, out ulong existingSequence)
            && existingSequence != PreferredAddressConnectionIdSequence)
        {
            errorCode = QuicTransportErrorCode.TransportParameterError;
            return false;
        }

        ulong activeCountAfterProcessing = (ulong)connectionIdsBySequence.Count + 1;
        if (activeCountAfterProcessing > activeConnectionIdLimit)
        {
            errorCode = QuicTransportErrorCode.ConnectionIdLimitError;
            return false;
        }

        ulong? previousDestinationSequence = currentDestinationConnectionIdSequence;
        byte[] previousDestinationConnectionId = currentDestinationConnectionId;

        connectionIdsBySequence.Add(PreferredAddressConnectionIdSequence, record);
        connectionIdHistoryBySequence.Add(PreferredAddressConnectionIdSequence, record);
        sequenceByConnectionId.Add(connectionIdKey, PreferredAddressConnectionIdSequence);

        // Preferred-address migration selects this CID through the path transition gate; recording it
        // here counts it against active_connection_id_limit without preempting the current path.
        destinationConnectionIdChanged =
            previousDestinationSequence != currentDestinationConnectionIdSequence
            || !previousDestinationConnectionId.AsSpan().SequenceEqual(currentDestinationConnectionId);

        return true;
    }

    internal bool TryUseDestinationConnectionIdOnPath(
        QuicConnectionPathIdentity pathIdentity,
        ulong activeConnectionIdLimit,
        bool retireInactivePathConnectionIds,
        out QuicTransportErrorCode errorCode,
        out bool destinationConnectionIdChanged,
        out ulong[] retiredSequenceNumbers)
    {
        errorCode = QuicTransportErrorCode.NoError;
        destinationConnectionIdChanged = false;
        retiredSequenceNumbers = [];

        if (!currentDestinationConnectionIdSequence.HasValue || connectionIdsBySequence.Count == 0)
        {
            return true;
        }

        ulong previousDestinationSequence = currentDestinationConnectionIdSequence.Value;
        byte[] previousDestinationConnectionId = currentDestinationConnectionId;
        ulong selectedSequence = previousDestinationSequence;

        if (TryFindBoundConnectionIdForPath(pathIdentity, out ulong boundSequence))
        {
            selectedSequence = boundSequence;
        }
        else if (pathBySequence.TryGetValue(selectedSequence, out QuicConnectionPathIdentity boundPath)
            && !PathIdentityEquals(boundPath, pathIdentity))
        {
            if (!TryFindAvailableConnectionIdForPath(pathIdentity, out selectedSequence))
            {
                if (!CanReuseCurrentConnectionIdForPeerAddressChange(boundPath, pathIdentity))
                {
                    return false;
                }

                selectedSequence = previousDestinationSequence;
            }
        }

        List<ulong>? sequencesToRetire = null;
        if (retireInactivePathConnectionIds)
        {
            foreach (KeyValuePair<ulong, QuicConnectionPathIdentity> entry in pathBySequence)
            {
                if (entry.Key == selectedSequence
                    || !connectionIdsBySequence.ContainsKey(entry.Key)
                    || PathIdentityEquals(entry.Value, pathIdentity))
                {
                    continue;
                }

                (sequencesToRetire ??= []).Add(entry.Key);
            }
        }

        if (sequencesToRetire is not null
            && !CanReportRetiredSequenceNumbers(sequencesToRetire, activeConnectionIdLimit, out errorCode))
        {
            return false;
        }

        SetCurrentDestinationConnectionId(selectedSequence);
        pathBySequence[selectedSequence] = pathIdentity;

        List<ulong>? newlyRetiredSequenceNumbers = null;
        if (sequencesToRetire is not null)
        {
            foreach (ulong sequenceNumber in sequencesToRetire)
            {
                connectionIdsBySequence.Remove(sequenceNumber);
                pathBySequence.Remove(sequenceNumber);
                if (retiredSequenceNumbersReportedToRuntime.Add(sequenceNumber))
                {
                    (newlyRetiredSequenceNumbers ??= []).Add(sequenceNumber);
                }
            }
        }

        retiredSequenceNumbers = newlyRetiredSequenceNumbers?.ToArray() ?? Array.Empty<ulong>();
        destinationConnectionIdChanged =
            previousDestinationSequence != currentDestinationConnectionIdSequence
            || !previousDestinationConnectionId.AsSpan().SequenceEqual(currentDestinationConnectionId);
        return true;
    }

    internal void BindCurrentDestinationConnectionIdToPath(QuicConnectionPathIdentity pathIdentity)
    {
        if (!currentDestinationConnectionIdSequence.HasValue
            || !connectionIdsBySequence.ContainsKey(currentDestinationConnectionIdSequence.Value))
        {
            return;
        }

        pathBySequence[currentDestinationConnectionIdSequence.Value] = pathIdentity;
    }

    /// <summary>
    /// Clears all peer connection ID state.
    /// </summary>
    internal void Clear()
    {
        connectionIdsBySequence.Clear();
        connectionIdHistoryBySequence.Clear();
        sequenceByConnectionId.Clear();
        pathBySequence.Clear();
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

        if (currentDestinationConnectionIdSequence.HasValue
            && connectionIdsBySequence.TryGetValue(
                currentDestinationConnectionIdSequence.Value,
                out QuicConnectionPeerConnectionIdRecord currentRecord))
        {
            currentDestinationConnectionId = currentRecord.ConnectionIdBytes;
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
        currentDestinationConnectionId = selectedRecord.ConnectionIdBytes;
    }

    private bool TryFindAvailableConnectionIdForPath(
        QuicConnectionPathIdentity pathIdentity,
        out ulong selectedSequence)
    {
        selectedSequence = 0;
        bool selected = false;

        foreach (ulong sequenceNumber in connectionIdsBySequence.Keys)
        {
            if (pathBySequence.TryGetValue(sequenceNumber, out QuicConnectionPathIdentity boundPath)
                && !PathIdentityEquals(boundPath, pathIdentity))
            {
                continue;
            }

            if (!selected || sequenceNumber > selectedSequence)
            {
                selectedSequence = sequenceNumber;
                selected = true;
            }
        }

        return selected;
    }

    private bool TryFindBoundConnectionIdForPath(
        QuicConnectionPathIdentity pathIdentity,
        out ulong selectedSequence)
    {
        selectedSequence = 0;
        bool selected = false;

        foreach (KeyValuePair<ulong, QuicConnectionPathIdentity> entry in pathBySequence)
        {
            if (!connectionIdsBySequence.ContainsKey(entry.Key)
                || !PathIdentityEquals(entry.Value, pathIdentity))
            {
                continue;
            }

            if (!selected || entry.Key > selectedSequence)
            {
                selectedSequence = entry.Key;
                selected = true;
            }
        }

        return selected;
    }

    private void SetCurrentDestinationConnectionId(ulong sequenceNumber)
    {
        if (!connectionIdsBySequence.TryGetValue(sequenceNumber, out QuicConnectionPeerConnectionIdRecord record))
        {
            RecomputeCurrentDestinationConnectionId();
            return;
        }

        currentDestinationConnectionIdSequence = sequenceNumber;
        currentDestinationConnectionId = record.ConnectionIdBytes;
    }

    private static bool PathIdentityEquals(
        QuicConnectionPathIdentity left,
        QuicConnectionPathIdentity right)
    {
        return string.Equals(left.RemoteAddress, right.RemoteAddress, StringComparison.Ordinal)
            && string.Equals(left.LocalAddress, right.LocalAddress, StringComparison.Ordinal)
            && left.RemotePort == right.RemotePort
            && left.LocalPort == right.LocalPort;
    }

    private static bool CanReuseCurrentConnectionIdForPeerAddressChange(
        QuicConnectionPathIdentity currentPath,
        QuicConnectionPathIdentity requestedPath)
    {
        return string.Equals(currentPath.LocalAddress, requestedPath.LocalAddress, StringComparison.Ordinal)
            && currentPath.LocalPort == requestedPath.LocalPort;
    }

    private bool CanReportRetiredSequenceNumbers(
        IEnumerable<ulong> sequenceNumbers,
        ulong activeConnectionIdLimit,
        out QuicTransportErrorCode errorCode)
    {
        errorCode = QuicTransportErrorCode.NoError;
        ulong pendingCount = (ulong)retiredSequenceNumbersReportedToRuntime.Count;
        ulong pendingLimit = GetPendingRetiredConnectionIdLimit(activeConnectionIdLimit);

        foreach (ulong sequenceNumber in sequenceNumbers)
        {
            if (retiredSequenceNumbersReportedToRuntime.Contains(sequenceNumber))
            {
                continue;
            }

            pendingCount++;
            if (pendingCount > pendingLimit)
            {
                errorCode = QuicTransportErrorCode.ConnectionIdLimitError;
                return false;
            }
        }

        return true;
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
