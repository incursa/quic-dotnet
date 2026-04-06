namespace Incursa.Quic;

internal enum QuicStreamSendState
{
    None = 0,
    Ready = 1,
    Send = 2,
    DataSent = 3,
    ResetSent = 4,
}
