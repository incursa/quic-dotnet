namespace Incursa.Quic;

internal readonly record struct QuicConnectionStreamSnapshot(
    ulong StreamId,
    QuicStreamType StreamType,
    QuicStreamSendState SendState,
    QuicStreamReceiveState ReceiveState,
    ulong SendLimit,
    ulong ReceiveLimit,
    ulong FinalSize,
    bool HasFinalSize,
    ulong UniqueBytesSent,
    ulong UniqueBytesReceived,
    ulong AccountedBytesReceived,
    ulong ReadOffset,
    int BufferedReadableBytes,
    ulong ReceiveAbortErrorCode,
    bool HasReceiveAbortErrorCode,
    ulong SendAbortErrorCode,
    bool HasSendAbortErrorCode);
