// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

/// <summary>
/// Tracks the connection IDs and stateless-reset tokens that the runtime has issued to the peer.
/// </summary>
internal sealed class QuicConnectionIssuedConnectionIdState
{
    private readonly Dictionary<ulong, byte[]> statelessResetTokensByConnectionId = [];
    private readonly Dictionary<ulong, byte[]> issuedConnectionIdBytesByConnectionId = [];
    private readonly HashSet<ulong> usedIssuedConnectionIds = [];
    private ulong highestConnectionIdIssuedToPeer;
    private ulong totalIssuedConnectionIdCount;

    internal Dictionary<ulong, byte[]> StatelessResetTokensByConnectionId => statelessResetTokensByConnectionId;

    internal Dictionary<ulong, byte[]> IssuedConnectionIdBytesByConnectionId => issuedConnectionIdBytesByConnectionId;

    internal ulong HighestConnectionIdIssuedToPeer => highestConnectionIdIssuedToPeer;

    internal ulong TotalIssuedConnectionIdCount => totalIssuedConnectionIdCount;

    internal int IssuedConnectionIdCount => statelessResetTokensByConnectionId.Count;

    internal void Reset()
    {
        statelessResetTokensByConnectionId.Clear();
        issuedConnectionIdBytesByConnectionId.Clear();
        usedIssuedConnectionIds.Clear();
        highestConnectionIdIssuedToPeer = 0;
        totalIssuedConnectionIdCount = 0;
    }

    internal bool CanIssueAnotherConnectionId(ulong maximumLocallyIssuedConnectionIds)
    {
        return totalIssuedConnectionIdCount < maximumLocallyIssuedConnectionIds;
    }

    internal bool HasRoomForAdditionalPeerIssuedConnectionId(ulong peerActiveConnectionIdLimit)
    {
        return (ulong)statelessResetTokensByConnectionId.Count + 1 < peerActiveConnectionIdLimit;
    }

    internal bool IsActiveIssuedConnectionId(ReadOnlySpan<byte> connectionIdBytes)
    {
        foreach (byte[] activeConnectionIdBytes in issuedConnectionIdBytesByConnectionId.Values)
        {
            if (activeConnectionIdBytes.AsSpan().SequenceEqual(connectionIdBytes))
            {
                return true;
            }
        }

        return false;
    }

    internal bool TryRegisterIssuedConnectionId(
        ulong connectionId,
        byte[]? connectionIdBytes,
        byte[] statelessResetToken,
        ulong peerActiveConnectionIdLimit)
    {
        if (statelessResetTokensByConnectionId.ContainsKey(connectionId)
            || !HasRoomForAdditionalPeerIssuedConnectionId(peerActiveConnectionIdLimit))
        {
            return false;
        }

        if (connectionIdBytes is not null)
        {
            if (IsActiveIssuedConnectionId(connectionIdBytes))
            {
                return false;
            }
        }

        statelessResetTokensByConnectionId.Add(connectionId, statelessResetToken);
        if (connectionIdBytes is not null)
        {
            issuedConnectionIdBytesByConnectionId.Add(connectionId, connectionIdBytes);
        }

        if (connectionId > highestConnectionIdIssuedToPeer)
        {
            highestConnectionIdIssuedToPeer = connectionId;
        }

        totalIssuedConnectionIdCount++;
        return true;
    }

    internal bool TryRetireIssuedConnectionId(ulong connectionId, out byte[]? connectionIdBytes)
    {
        connectionIdBytes = null;
        if (!statelessResetTokensByConnectionId.Remove(connectionId, out _))
        {
            return false;
        }

        usedIssuedConnectionIds.Remove(connectionId);
        issuedConnectionIdBytesByConnectionId.Remove(connectionId, out connectionIdBytes);
        return true;
    }

    internal bool TryMarkIssuedConnectionIdUsed(ulong connectionId)
    {
        return statelessResetTokensByConnectionId.ContainsKey(connectionId)
            && issuedConnectionIdBytesByConnectionId.ContainsKey(connectionId)
            && usedIssuedConnectionIds.Add(connectionId);
    }

}
