namespace Incursa.Quic.Tests;

internal static class QuicAckEcnFrameCodecTestSupport
{
    internal static QuicAckFrame CreateAckEcnFrame(ulong ect0Count, ulong ect1Count, ulong ecnCeCount)
    {
        return new QuicAckFrame
        {
            FrameType = 0x03,
            LargestAcknowledged = 4,
            AckDelay = 1,
            FirstAckRange = 0,
            EcnCounts = new QuicEcnCounts(ect0Count, ect1Count, ecnCeCount),
        };
    }

    internal static byte[] FormatAckFrame(QuicAckFrame frame)
    {
        byte[] destination = new byte[64];
        Assert.True(QuicFrameCodec.TryFormatAckFrame(frame, destination, out int bytesWritten));
        return destination[..bytesWritten];
    }

    internal static QuicAckFrame ParseAckFrame(byte[] encoded)
    {
        Assert.True(QuicFrameCodec.TryParseAckFrame(encoded, out QuicAckFrame parsed, out int bytesConsumed));
        Assert.Equal(encoded.Length, bytesConsumed);
        return parsed;
    }

    internal static void AssertEcnCountsRoundTrip(ulong ect0Count, ulong ect1Count, ulong ecnCeCount)
    {
        QuicAckFrame frame = CreateAckEcnFrame(ect0Count, ect1Count, ecnCeCount);
        byte[] encoded = FormatAckFrame(frame);
        QuicAckFrame parsed = ParseAckFrame(encoded);

        Assert.Equal(0x03, parsed.FrameType);
        Assert.NotNull(parsed.EcnCounts);
        Assert.Equal(ect0Count, parsed.EcnCounts.Value.Ect0Count);
        Assert.Equal(ect1Count, parsed.EcnCounts.Value.Ect1Count);
        Assert.Equal(ecnCeCount, parsed.EcnCounts.Value.EcnCeCount);
    }

    internal static (ulong Value, int BytesConsumed) ParseEcnCountField(byte[] encoded, int fieldIndex)
    {
        const int EcnCountStartIndex = 5;
        int index = EcnCountStartIndex;
        ulong value = 0;
        int bytesConsumed = 0;

        for (int currentField = 0; currentField <= fieldIndex; currentField++)
        {
            Assert.True(QuicVariableLengthInteger.TryParse(encoded.AsSpan(index), out value, out bytesConsumed));
            index += bytesConsumed;
        }

        return (value, bytesConsumed);
    }
}
