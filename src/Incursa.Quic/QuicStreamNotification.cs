// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

// CONTEXT: Stream notifications use a stable discriminant plus optional exception because the
// callback surface needs to distinguish lifecycle events from faulted completions.
// SEE: QuicStream
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

internal interface IQuicStreamNotificationObserver
{
    void OnStreamNotification(QuicStreamNotification notification);
}
