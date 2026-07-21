// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

internal enum QuicReceiveCreditPolicyMode
{
    LegacyCurrent = 0,
    Immediate = 1,
    ReadDominantBatch = 2,
}

internal static class QuicReceiveCreditPolicy
{
    internal const ushort ReadDominantMinimumLiveObserverStreams = 16;
}
