namespace Incursa.Quic;

internal readonly record struct QuicConnectionStreamStateOptions(
    bool IsServer,
    ulong InitialConnectionReceiveLimit,
    ulong InitialConnectionSendLimit,
    ulong InitialIncomingBidirectionalStreamLimit,
    ulong InitialIncomingUnidirectionalStreamLimit,
    ulong InitialPeerBidirectionalStreamLimit,
    ulong InitialPeerUnidirectionalStreamLimit,
    ulong InitialLocalBidirectionalReceiveLimit,
    ulong InitialPeerBidirectionalReceiveLimit,
    ulong InitialPeerUnidirectionalReceiveLimit,
    ulong InitialLocalBidirectionalSendLimit,
    ulong InitialLocalUnidirectionalSendLimit,
    ulong InitialPeerBidirectionalSendLimit);
