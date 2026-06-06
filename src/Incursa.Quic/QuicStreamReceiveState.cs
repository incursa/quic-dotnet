// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

// CONTEXT: The receive-state values are ordered to match the stream-state machine transitions used
// by the bookkeeping layer, so the numeric sequence is intentional.
// SEE: QuicConnectionStreamState
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
