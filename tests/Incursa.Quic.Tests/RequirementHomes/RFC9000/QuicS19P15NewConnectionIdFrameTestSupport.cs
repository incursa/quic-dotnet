namespace Incursa.Quic.Tests;

internal static class QuicS19P15NewConnectionIdFrameTestSupport
{
    internal const byte NewConnectionIdFrameType = 0x18;
    internal const int StatelessResetTokenLength = 16;

    internal static byte[] BuildNewConnectionIdFrame(
        ulong sequenceNumber,
        ulong retirePriorTo,
        ReadOnlySpan<byte> connectionId,
        ReadOnlySpan<byte> statelessResetToken)
    {
        return BuildNewConnectionIdFrameWithLengthBytes(
            QuicVarintTestData.EncodeMinimal(NewConnectionIdFrameType),
            QuicVarintTestData.EncodeMinimal(sequenceNumber),
            QuicVarintTestData.EncodeMinimal(retirePriorTo),
            [(byte)connectionId.Length],
            connectionId,
            statelessResetToken);
    }

    internal static byte[] BuildNewConnectionIdFrameWithEncodedType(
        int encodedTypeLength,
        ulong sequenceNumber,
        ulong retirePriorTo,
        ReadOnlySpan<byte> connectionId,
        ReadOnlySpan<byte> statelessResetToken)
    {
        return BuildNewConnectionIdFrameWithLengthBytes(
            QuicVarintTestData.EncodeWithLength(NewConnectionIdFrameType, encodedTypeLength),
            QuicVarintTestData.EncodeMinimal(sequenceNumber),
            QuicVarintTestData.EncodeMinimal(retirePriorTo),
            [(byte)connectionId.Length],
            connectionId,
            statelessResetToken);
    }

    internal static byte[] BuildNewConnectionIdFrameWithEncodedSequenceNumber(
        ulong sequenceNumber,
        int encodedSequenceNumberLength,
        ulong retirePriorTo,
        ReadOnlySpan<byte> connectionId,
        ReadOnlySpan<byte> statelessResetToken)
    {
        return BuildNewConnectionIdFrameWithLengthBytes(
            QuicVarintTestData.EncodeMinimal(NewConnectionIdFrameType),
            QuicVarintTestData.EncodeWithLength(sequenceNumber, encodedSequenceNumberLength),
            QuicVarintTestData.EncodeMinimal(retirePriorTo),
            [(byte)connectionId.Length],
            connectionId,
            statelessResetToken);
    }

    internal static byte[] BuildNewConnectionIdFrameWithEncodedRetirePriorTo(
        ulong sequenceNumber,
        ulong retirePriorTo,
        int encodedRetirePriorToLength,
        ReadOnlySpan<byte> connectionId,
        ReadOnlySpan<byte> statelessResetToken)
    {
        return BuildNewConnectionIdFrameWithLengthBytes(
            QuicVarintTestData.EncodeMinimal(NewConnectionIdFrameType),
            QuicVarintTestData.EncodeMinimal(sequenceNumber),
            QuicVarintTestData.EncodeWithLength(retirePriorTo, encodedRetirePriorToLength),
            [(byte)connectionId.Length],
            connectionId,
            statelessResetToken);
    }

    internal static byte[] BuildNewConnectionIdFrameWithLengthBytes(
        ReadOnlySpan<byte> typeBytes,
        ReadOnlySpan<byte> sequenceNumberBytes,
        ReadOnlySpan<byte> retirePriorToBytes,
        ReadOnlySpan<byte> connectionIdLengthBytes,
        ReadOnlySpan<byte> connectionId,
        ReadOnlySpan<byte> statelessResetToken)
    {
        byte[] frame = new byte[
            typeBytes.Length
            + sequenceNumberBytes.Length
            + retirePriorToBytes.Length
            + connectionIdLengthBytes.Length
            + connectionId.Length
            + statelessResetToken.Length];
        int index = 0;

        typeBytes.CopyTo(frame.AsSpan(index));
        index += typeBytes.Length;

        sequenceNumberBytes.CopyTo(frame.AsSpan(index));
        index += sequenceNumberBytes.Length;

        retirePriorToBytes.CopyTo(frame.AsSpan(index));
        index += retirePriorToBytes.Length;

        connectionIdLengthBytes.CopyTo(frame.AsSpan(index));
        index += connectionIdLengthBytes.Length;

        connectionId.CopyTo(frame.AsSpan(index));
        index += connectionId.Length;

        statelessResetToken.CopyTo(frame.AsSpan(index));
        return frame;
    }

    internal static byte[] CreateConnectionId(int length, byte firstByte = 0x30)
    {
        byte[] connectionId = new byte[length];
        for (int index = 0; index < connectionId.Length; index++)
        {
            connectionId[index] = (byte)(firstByte + index);
        }

        return connectionId;
    }

    internal static byte[] CreateStatelessResetToken(byte firstByte = 0x80)
    {
        byte[] token = new byte[StatelessResetTokenLength];
        for (int index = 0; index < token.Length; index++)
        {
            token[index] = (byte)(firstByte + index);
        }

        return token;
    }

    internal static void AssertParses(
        ReadOnlySpan<byte> frameBytes,
        ulong expectedSequenceNumber,
        ulong expectedRetirePriorTo,
        ReadOnlySpan<byte> expectedConnectionId,
        ReadOnlySpan<byte> expectedStatelessResetToken,
        int? expectedBytesConsumed = null)
    {
        Assert.True(QuicFrameCodec.TryParseNewConnectionIdFrame(frameBytes, out QuicNewConnectionIdFrame frame, out int bytesConsumed));
        Assert.Equal(expectedBytesConsumed ?? frameBytes.Length, bytesConsumed);
        Assert.Equal(expectedSequenceNumber, frame.SequenceNumber);
        Assert.Equal(expectedRetirePriorTo, frame.RetirePriorTo);
        Assert.True(expectedConnectionId.SequenceEqual(frame.ConnectionId));
        Assert.True(expectedStatelessResetToken.SequenceEqual(frame.StatelessResetToken));
    }

    internal static void AssertRejects(ReadOnlySpan<byte> frameBytes)
    {
        Assert.False(QuicFrameCodec.TryParseNewConnectionIdFrame(frameBytes, out _, out _));
    }
}
