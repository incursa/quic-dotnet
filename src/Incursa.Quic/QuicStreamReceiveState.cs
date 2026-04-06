namespace Incursa.Quic;

internal enum QuicStreamReceiveState
{
    None = 0,
    Recv = 1,
    SizeKnown = 2,
    DataRecvd = 3,
    DataRead = 4,
    ResetRecvd = 5,
    ResetRead = 6,
}
