namespace Incursa.Quic;

internal sealed class QuicConnectionPeerConnectionIdState
{
    private readonly Dictionary<ulong, QuicConnectionPeerConnectionIdRecord> connectionIdsBySequence = [];
    private readonly Dictionary<QuicConnectionIdKey, ulong> sequenceByConnectionId = [];
    private byte[] currentDestinationConnectionId = [];
    private ulong? currentDestinationConnectionIdSequence;

    internal ReadOnlyMemory<byte> CurrentDestinationConnectionId => currentDestinationConnectionId;

    internal ulong? CurrentDestinationConnectionIdSequence => currentDestinationConnectionIdSequence;

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

    internal void Clear()
    {
        connectionIdsBySequence.Clear();
        sequenceByConnectionId.Clear();
        currentDestinationConnectionId = [];
        currentDestinationConnectionIdSequence = null;
    }

    private readonly record struct QuicConnectionPeerConnectionIdRecord(
        QuicConnectionIdKey ConnectionId,
        ulong RetirePriorTo,
        byte[] StatelessResetToken);
}
