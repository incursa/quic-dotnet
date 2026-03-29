using System.Buffers.Binary;

namespace Incursa.Quic.Tests;

internal static class QuicFrameTestData
{
    public static byte[] BuildPaddingFrame()
    {
        return [0x00];
    }

    public static byte[] BuildPingFrame()
    {
        return [0x01];
    }

    public static byte[] BuildAckFrame(QuicAckFrame frame)
    {
        if (frame is null)
        {
            throw new ArgumentNullException(nameof(frame));
        }

        List<byte> bytes = [];
        bytes.AddRange(EncodeVarint(frame.FrameType));
        bytes.AddRange(EncodeVarint(frame.LargestAcknowledged));
        bytes.AddRange(EncodeVarint(frame.AckDelay));
        bytes.AddRange(EncodeVarint(frame.AckRangeCount));
        bytes.AddRange(EncodeVarint(frame.FirstAckRange));

        foreach (QuicAckRange additionalRange in frame.AdditionalRanges ?? [])
        {
            bytes.AddRange(EncodeVarint(additionalRange.Gap));
            bytes.AddRange(EncodeVarint(additionalRange.AckRangeLength));
        }

        if (frame.EcnCounts is QuicEcnCounts ecnCounts)
        {
            bytes.AddRange(EncodeVarint(ecnCounts.Ect0Count));
            bytes.AddRange(EncodeVarint(ecnCounts.Ect1Count));
            bytes.AddRange(EncodeVarint(ecnCounts.EcnCeCount));
        }

        return bytes.ToArray();
    }

    public static QuicAckRange BuildAckRange(ulong previousSmallestAcknowledged, ulong gap, ulong ackRangeLength)
    {
        if (previousSmallestAcknowledged < gap + 2)
        {
            throw new ArgumentOutOfRangeException(nameof(gap));
        }

        ulong largestAcknowledged = previousSmallestAcknowledged - gap - 2;
        if (largestAcknowledged < ackRangeLength)
        {
            throw new ArgumentOutOfRangeException(nameof(ackRangeLength));
        }

        ulong smallestAcknowledged = largestAcknowledged - ackRangeLength;
        return new QuicAckRange(gap, ackRangeLength, smallestAcknowledged, largestAcknowledged);
    }

    public static byte[] BuildResetStreamFrame(QuicResetStreamFrame frame)
    {
        List<byte> bytes = [];
        bytes.AddRange(EncodeVarint(0x04));
        bytes.AddRange(EncodeVarint(frame.StreamId));
        bytes.AddRange(EncodeVarint(frame.ApplicationProtocolErrorCode));
        bytes.AddRange(EncodeVarint(frame.FinalSize));
        return bytes.ToArray();
    }

    public static byte[] BuildStopSendingFrame(QuicStopSendingFrame frame)
    {
        List<byte> bytes = [];
        bytes.AddRange(EncodeVarint(0x05));
        bytes.AddRange(EncodeVarint(frame.StreamId));
        bytes.AddRange(EncodeVarint(frame.ApplicationProtocolErrorCode));
        return bytes.ToArray();
    }

    private static byte[] EncodeVarint(ulong value)
    {
        Span<byte> buffer = stackalloc byte[8];
        Assert.True(QuicVariableLengthInteger.TryFormat(value, buffer, out int bytesWritten));
        return buffer[..bytesWritten].ToArray();
    }
}
