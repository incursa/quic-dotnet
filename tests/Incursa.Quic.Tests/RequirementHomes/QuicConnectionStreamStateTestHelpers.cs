namespace Incursa.Quic.Tests;

internal static class QuicConnectionStreamStateTestHelpers
{
    internal static QuicConnectionStreamState CreateState(
        bool isServer = false,
        ulong connectionReceiveLimit = 64,
        ulong connectionSendLimit = 64,
        ulong incomingBidirectionalStreamLimit = 4,
        ulong incomingUnidirectionalStreamLimit = 4,
        ulong peerBidirectionalStreamLimit = 4,
        ulong peerUnidirectionalStreamLimit = 4,
        ulong localBidirectionalReceiveLimit = 8,
        ulong peerBidirectionalReceiveLimit = 8,
        ulong peerUnidirectionalReceiveLimit = 8,
        ulong localBidirectionalSendLimit = 8,
        ulong localUnidirectionalSendLimit = 8,
        ulong peerBidirectionalSendLimit = 8)
    {
        return new QuicConnectionStreamState(
            new QuicConnectionStreamStateOptions(
                IsServer: isServer,
                InitialConnectionReceiveLimit: connectionReceiveLimit,
                InitialConnectionSendLimit: connectionSendLimit,
                InitialIncomingBidirectionalStreamLimit: incomingBidirectionalStreamLimit,
                InitialIncomingUnidirectionalStreamLimit: incomingUnidirectionalStreamLimit,
                InitialPeerBidirectionalStreamLimit: peerBidirectionalStreamLimit,
                InitialPeerUnidirectionalStreamLimit: peerUnidirectionalStreamLimit,
                InitialLocalBidirectionalReceiveLimit: localBidirectionalReceiveLimit,
                InitialPeerBidirectionalReceiveLimit: peerBidirectionalReceiveLimit,
                InitialPeerUnidirectionalReceiveLimit: peerUnidirectionalReceiveLimit,
                InitialLocalBidirectionalSendLimit: localBidirectionalSendLimit,
                InitialLocalUnidirectionalSendLimit: localUnidirectionalSendLimit,
                InitialPeerBidirectionalSendLimit: peerBidirectionalSendLimit));
    }
}
