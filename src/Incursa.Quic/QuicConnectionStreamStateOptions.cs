namespace Incursa.Quic;

/// <summary>
/// Supplies the initial flow-control and stream-limit settings used to initialize connection stream state.
/// </summary>
/// <param name="IsServer">Whether the owning endpoint is acting as the server.</param>
/// <param name="InitialConnectionReceiveLimit">The initial connection-level receive window.</param>
/// <param name="InitialConnectionSendLimit">The initial connection-level send window.</param>
/// <param name="InitialIncomingBidirectionalStreamLimit">The initial limit for peer-initiated bidirectional streams.</param>
/// <param name="InitialIncomingUnidirectionalStreamLimit">The initial limit for peer-initiated unidirectional streams.</param>
/// <param name="InitialPeerBidirectionalStreamLimit">The initial bidirectional stream limit advertised to the peer.</param>
/// <param name="InitialPeerUnidirectionalStreamLimit">The initial unidirectional stream limit advertised to the peer.</param>
/// <param name="InitialLocalBidirectionalReceiveLimit">The initial receive limit for locally initiated bidirectional streams.</param>
/// <param name="InitialPeerBidirectionalReceiveLimit">The initial receive limit for peer-initiated bidirectional streams.</param>
/// <param name="InitialPeerUnidirectionalReceiveLimit">The initial receive limit for peer-initiated unidirectional streams.</param>
/// <param name="InitialLocalBidirectionalSendLimit">The initial send limit for locally initiated bidirectional streams.</param>
/// <param name="InitialLocalUnidirectionalSendLimit">The initial send limit for locally initiated unidirectional streams.</param>
/// <param name="InitialPeerBidirectionalSendLimit">The initial send limit for peer-initiated bidirectional streams.</param>
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
