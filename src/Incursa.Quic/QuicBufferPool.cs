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

        return ArrayPool<byte>.Shared.Rent(minimumLength);
    }

    internal static QuicBufferLease RentLease(int minimumLength)
    {
        return new QuicBufferLease(RentBytes(minimumLength));
    }

    internal static void ReturnBytes(byte[]? buffer, bool clearArray = false)
    {
        if (buffer is null)
        {
            return;
        }

        ArrayPool<byte>.Shared.Return(buffer, clearArray);
    }
}
