namespace Incursa.Quic;

/// <summary>
/// Captures the observable bookkeeping state for a stream at a single point in time.
/// </summary>
/// <param name="StreamId">The stream identifier.</param>
/// <param name="StreamType">The stream directionality and endpoint ownership.</param>
/// <param name="SendState">The current send-side state machine value.</param>
/// <param name="ReceiveState">The current receive-side state machine value.</param>
/// <param name="SendLimit">The maximum send offset currently allowed.</param>
/// <param name="ReceiveLimit">The maximum receive offset currently allowed.</param>
/// <param name="FinalSize">The final stream size, when known.</param>
/// <param name="HasFinalSize">Indicates whether <paramref name="FinalSize" /> is valid.</param>
/// <param name="UniqueBytesSent">The number of unique bytes sent on the stream.</param>
/// <param name="UniqueBytesReceived">The number of unique bytes received on the stream.</param>
/// <param name="AccountedBytesReceived">The number of received bytes already counted toward buffered/readable state.</param>
/// <param name="ReadOffset">The current application read offset.</param>
/// <param name="BufferedReadableBytes">The number of bytes currently buffered and readable by the application.</param>
/// <param name="ReceiveAbortErrorCode">The receive-side application error code, when present.</param>
/// <param name="HasReceiveAbortErrorCode">Indicates whether <paramref name="ReceiveAbortErrorCode" /> is valid.</param>
/// <param name="SendAbortErrorCode">The send-side application error code, when present.</param>
/// <param name="HasSendAbortErrorCode">Indicates whether <paramref name="SendAbortErrorCode" /> is valid.</param>
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
