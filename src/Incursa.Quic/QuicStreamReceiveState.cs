// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

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
