namespace Incursa.Quic;

internal enum QuicStreamNotificationKind
{
    ReadAborted = 0,
    WriteAborted = 1,
    ConnectionTerminated = 2,
    DataAvailable = 3,
}

internal readonly record struct QuicStreamNotification(
    QuicStreamNotificationKind Kind,
    Exception? Exception);
