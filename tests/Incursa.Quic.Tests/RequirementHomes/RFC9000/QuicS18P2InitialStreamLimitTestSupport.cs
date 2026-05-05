namespace Incursa.Quic.Tests;

internal static class QuicS18P2InitialStreamLimitTestSupport
{
    internal const ulong InitialMaxStreamsBidiId = 0x08;
    internal const ulong InitialMaxStreamsUniId = 0x09;
    internal const ulong MaximumInitialStreamLimit = 1UL << 60;

    internal static byte[] BuildInitialStreamLimitParameter(ulong id, ulong value)
    {
        return QuicTransportParameterTestData.BuildTransportParameterTuple(
            id,
            QuicVarintTestData.EncodeMinimal(value));
    }

    internal static QuicTransportParameters ParseInitialStreamLimitParameter(ulong id, ulong value)
    {
        byte[] encoded = BuildInitialStreamLimitParameter(id, value);
        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            encoded,
            QuicTransportParameterRole.Client,
            out QuicTransportParameters parsed));

        return parsed;
    }

    internal static byte[] FormatTransportParameters(QuicTransportParameters parameters)
    {
        byte[] encoded = new byte[32];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            QuicTransportParameterRole.Client,
            encoded,
            out int bytesWritten));

        return encoded[..bytesWritten];
    }
}
