// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers;

namespace Incursa.Quic;

internal enum QuicBufferPoolOwner
{
    Other,
    Acknowledgment,
    Handshake,
    InboundDatagram,
    ReceiveSegment,
    StreamWriteRequest,
    OutboundStreamPayload,
    CombinedApplicationSend,
    InboundPacketProtection,
    OutboundPacketProtection,
    SentPacketRetention,
    Retransmission,
    ControlFrame,
    ListenerResponse,
    Count,
}

internal static class QuicBufferPool
{
    internal static byte[] RentBytes(
        int minimumLength,
        QuicBufferPoolOwner owner = QuicBufferPoolOwner.Other)
    {
        if (minimumLength < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(minimumLength));
        }

        if (owner is < QuicBufferPoolOwner.Other or >= QuicBufferPoolOwner.Count)
        {
            throw new ArgumentOutOfRangeException(nameof(owner));
        }

        byte[] buffer = ArrayPool<byte>.Shared.Rent(minimumLength);
        QuicMetrics.RecordBufferRent(minimumLength, buffer.Length, owner);
        return buffer;
    }

    // CONTEXT: array-pool returns are opt-in cleared to preserve hot-path throughput
    // SEE: code:src/Incursa.Quic/QuicBufferPool.cs#ReturnBytes
    // Most pooled buffers are immediately overwritten, so clearing on every
    // return would add unnecessary cost. Callers pass clearArray:true when a
    // buffer has carried secret material or other sensitive state that must
    // not linger in the pool.
    internal static QuicBufferLease RentLease(
        int minimumLength,
        QuicBufferPoolOwner owner = QuicBufferPoolOwner.Other)
    {
        return new QuicBufferLease(RentBytes(minimumLength, owner), minimumLength);
    }

    internal static void ReturnBytes(byte[]? buffer, bool clearArray = false)
    {
        if (buffer is null)
        {
            return;
        }

        QuicMetrics.RecordBufferReturn(buffer.Length);
        ArrayPool<byte>.Shared.Return(buffer, clearArray);
    }
}
