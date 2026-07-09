// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers;

namespace Incursa.Quic;

internal static class QuicBufferPool
{
    internal static byte[] RentBytes(int minimumLength)
    {
        if (minimumLength < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(minimumLength));
        }

        byte[] buffer = ArrayPool<byte>.Shared.Rent(minimumLength);
        QuicMetrics.RecordBufferRent(minimumLength, buffer.Length);
        return buffer;
    }

    // CONTEXT: array-pool returns are opt-in cleared to preserve hot-path throughput
    // SEE: code:src/Incursa.Quic/QuicBufferPool.cs#ReturnBytes
    // Most pooled buffers are immediately overwritten, so clearing on every
    // return would add unnecessary cost. Callers pass clearArray:true when a
    // buffer has carried secret material or other sensitive state that must
    // not linger in the pool.
    internal static QuicBufferLease RentLease(int minimumLength)
    {
        return new QuicBufferLease(RentBytes(minimumLength), minimumLength);
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
