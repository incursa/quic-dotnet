// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

internal static class Http3FrameTypes
{
    // CONTEXT: HTTP/3 reserves these frame types so unknown-frame handling can distinguish explicit
    // reservations and GREASE values from ordinary extension frames.
    // SEE: spec:REQ-QUIC-RFC9114-S4-0002
    // SEE: code:src/Incursa.Quic.Http3/Http3Frame.cs#IsReserved
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
