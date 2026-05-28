// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

internal struct QuicBufferLease : IDisposable
{
    private byte[]? buffer;
    private int length;

    internal QuicBufferLease(byte[] buffer)
    {
        this.buffer = buffer;
        length = buffer.Length;
    }

    internal int Length => length;

    internal Span<byte> Span => buffer is null
        ? Span<byte>.Empty
        : buffer.AsSpan(0, length);

    internal ReadOnlyMemory<byte> Memory => buffer is null
        ? ReadOnlyMemory<byte>.Empty
        : buffer.AsMemory(0, length);

    internal byte[] TransferOwnership(out int transferredLength)
    {
        if (buffer is null)
        {
            throw new ObjectDisposedException(nameof(QuicBufferLease));
        }

        byte[] transferredBuffer = buffer;
        transferredLength = length;
        buffer = null;
        length = 0;
        return transferredBuffer;
    }

    internal void SetLength(int length)
    {
        if (buffer is null)
        {
            throw new ObjectDisposedException(nameof(QuicBufferLease));
        }

        if ((uint)length > (uint)buffer.Length)
        {
            throw new ArgumentOutOfRangeException(nameof(length));
        }

        this.length = length;
    }

    public void Dispose()
    {
        byte[]? leasedBuffer = buffer;
        if (leasedBuffer is null)
        {
            return;
        }

        buffer = null;
        length = 0;
        QuicBufferPool.ReturnBytes(leasedBuffer);
    }
}
