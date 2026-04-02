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

    public static byte[] BuildConnectionCloseFrame(QuicConnectionCloseFrame frame)
    {
        List<byte> bytes = [];
        bytes.AddRange(EncodeVarint(frame.FrameType));
        bytes.AddRange(EncodeVarint(frame.ErrorCode));

        if (frame.HasTriggeringFrameType)
        {
            bytes.AddRange(EncodeVarint(frame.TriggeringFrameType));
        }

        bytes.AddRange(EncodeVarint((ulong)frame.ReasonPhrase.Length));
        bytes.AddRange(frame.ReasonPhrase.ToArray());
        return bytes.ToArray();
    }

    public static byte[] BuildHandshakeDoneFrame()
    {
        return [0x1E];
    }

    public static byte[] BuildCryptoFrame(QuicCryptoFrame frame)
    {
        List<byte> bytes = [];
        bytes.AddRange(EncodeVarint(0x06));
        bytes.AddRange(EncodeVarint(frame.Offset));
        bytes.AddRange(EncodeVarint((ulong)frame.CryptoData.Length));
        bytes.AddRange(frame.CryptoData.ToArray());
        return bytes.ToArray();
    }

    public static byte[] BuildNewTokenFrame(QuicNewTokenFrame frame)
    {
        List<byte> bytes = [];
        bytes.AddRange(EncodeVarint(0x07));
        bytes.AddRange(EncodeVarint((ulong)frame.Token.Length));
        bytes.AddRange(frame.Token.ToArray());
        return bytes.ToArray();
    }

    public static byte[] BuildMaxDataFrame(QuicMaxDataFrame frame)
    {
        List<byte> bytes = [];
        bytes.AddRange(EncodeVarint(0x10));
        bytes.AddRange(EncodeVarint(frame.MaximumData));
        return bytes.ToArray();
    }

    public static byte[] BuildMaxStreamDataFrame(QuicMaxStreamDataFrame frame)
    {
        List<byte> bytes = [];
        bytes.AddRange(EncodeVarint(0x11));
        bytes.AddRange(EncodeVarint(frame.StreamId));
        bytes.AddRange(EncodeVarint(frame.MaximumStreamData));
        return bytes.ToArray();
    }

    public static byte[] BuildMaxStreamsFrame(QuicMaxStreamsFrame frame)
    {
        List<byte> bytes = [];
        bytes.AddRange(EncodeVarint((ulong)(frame.IsBidirectional ? 0x12 : 0x13)));
        bytes.AddRange(EncodeVarint(frame.MaximumStreams));
        return bytes.ToArray();
    }

    public static byte[] BuildDataBlockedFrame(QuicDataBlockedFrame frame)
    {
        List<byte> bytes = [];
        bytes.AddRange(EncodeVarint(0x14));
        bytes.AddRange(EncodeVarint(frame.MaximumData));
        return bytes.ToArray();
    }

    public static byte[] BuildStreamDataBlockedFrame(QuicStreamDataBlockedFrame frame)
    {
        List<byte> bytes = [];
        bytes.AddRange(EncodeVarint(0x15));
        bytes.AddRange(EncodeVarint(frame.StreamId));
        bytes.AddRange(EncodeVarint(frame.MaximumStreamData));
        return bytes.ToArray();
    }

    public static byte[] BuildStreamsBlockedFrame(QuicStreamsBlockedFrame frame)
    {
        List<byte> bytes = [];
        bytes.AddRange(EncodeVarint((ulong)(frame.IsBidirectional ? 0x16 : 0x17)));
        bytes.AddRange(EncodeVarint(frame.MaximumStreams));
        return bytes.ToArray();
    }

    public static byte[] BuildNewConnectionIdFrame(QuicNewConnectionIdFrame frame)
    {
        List<byte> bytes = [];
        bytes.AddRange(EncodeVarint(0x18));
        bytes.AddRange(EncodeVarint(frame.SequenceNumber));
        bytes.AddRange(EncodeVarint(frame.RetirePriorTo));
        bytes.Add((byte)frame.ConnectionId.Length);
        bytes.AddRange(frame.ConnectionId.ToArray());
        bytes.AddRange(frame.StatelessResetToken.ToArray());
        return bytes.ToArray();
    }

    public static byte[] BuildRetireConnectionIdFrame(QuicRetireConnectionIdFrame frame)
    {
        List<byte> bytes = [];
        bytes.AddRange(EncodeVarint(0x19));
        bytes.AddRange(EncodeVarint(frame.SequenceNumber));
        return bytes.ToArray();
    }

    public static byte[] BuildPathChallengeFrame(QuicPathChallengeFrame frame)
    {
        List<byte> bytes = [];
        bytes.AddRange(EncodeVarint(0x1A));
        bytes.AddRange(frame.Data.ToArray());
        return bytes.ToArray();
    }

    public static byte[] BuildPathResponseFrame(QuicPathResponseFrame frame)
    {
        List<byte> bytes = [];
        bytes.AddRange(EncodeVarint(0x1B));
        bytes.AddRange(frame.Data.ToArray());
        return bytes.ToArray();
    }

    private static byte[] EncodeVarint(ulong value)
    {
        Span<byte> buffer = stackalloc byte[8];
        Assert.True(QuicVariableLengthInteger.TryFormat(value, buffer, out int bytesWritten));
        return buffer[..bytesWritten].ToArray();
    }
}
