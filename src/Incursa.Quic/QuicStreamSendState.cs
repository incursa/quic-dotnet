// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

internal enum QuicStreamSendState
{
    None = 0,
    Ready = 1,
    Send = 2,
    DataSent = 3,
    ResetSent = 4,
    DataRecvd = 5,
    ResetRecvd = 6,
}
