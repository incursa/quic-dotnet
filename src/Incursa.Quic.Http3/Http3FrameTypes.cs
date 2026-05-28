// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

internal static class Http3FrameTypes
{
    private const ulong ReservedGreaseTypeOffset = 0x21;
    private const ulong ReservedGreaseTypeModulus = 0x1F;
    private const ulong ReservedPriorityFrameType = 0x02;
    private const ulong ReservedHttp2PingFrameType = 0x06;
    private const ulong ReservedHttp2ContinuationFrameType = 0x09;
    private const ulong ReservedHttp2WindowUpdateFrameType = 0x08;

    internal static bool IsReserved(ulong frameType)
    {
        return frameType is ReservedPriorityFrameType
            or ReservedHttp2PingFrameType
            or ReservedHttp2ContinuationFrameType
            or ReservedHttp2WindowUpdateFrameType
            || frameType >= ReservedGreaseTypeOffset
            && (frameType - ReservedGreaseTypeOffset) % ReservedGreaseTypeModulus == 0;
    }
}
