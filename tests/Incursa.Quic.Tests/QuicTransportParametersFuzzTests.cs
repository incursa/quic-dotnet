namespace Incursa.Quic.Tests;

public sealed class QuicTransportParametersFuzzTests
{
    [Fact]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S18-0002")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S18-0003")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S18-0004")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S18-0005")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S18-0006")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S18-0007")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S18P1-0001")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S18P1-0002")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S18P2-0001")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S18P2-0002")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S18P2-0004")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S18P2-0005")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S18P2-0007")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S18P2-0008")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S18P2-0010")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S18P2-0013")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S18P2-0015")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S18P2-0016")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S18P2-0019")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S18P2-0020")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S18P2-0021")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S18P2-0022")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S18P2-0023")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S18P2-0025")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S18P2-0026")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S18P2-0028")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S18P2-0029")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S18P2-0030")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S18P2-0031")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S18P2-0032")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S18P2-0033")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S18P2-0035")]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TransportParameters_RoundTripsRepresentativeValuesAndRejectsTruncation()
    {
        Random random = new(0x5150_2030);
        Span<byte> destination = stackalloc byte[256];

        for (int iteration = 0; iteration < 128; iteration++)
        {
            QuicTransportParameters parameters = BuildRandomParameters(random);

            Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
                parameters,
                QuicTransportParameterRole.Server,
                destination,
                out int bytesWritten));

            byte[] baseEncoded = destination[..bytesWritten].ToArray();
            byte[] encoded = baseEncoded;
            if ((iteration & 1) == 0)
            {
                byte[] greaseTuple = QuicTransportParameterTestData.BuildTransportParameterTuple(
                    27,
                    new[] { (byte)random.Next(0, 256), (byte)random.Next(0, 256), (byte)random.Next(0, 256) });
                encoded = QuicTransportParameterTestData.BuildTransportParameterBlock(baseEncoded, greaseTuple);
            }

            Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
                encoded,
                QuicTransportParameterRole.Client,
                out QuicTransportParameters parsed));

            AssertTransportParametersEqual(parameters, parsed);

            if (baseEncoded.Length > 1)
            {
                byte[] truncated = baseEncoded[..^1];

                Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
                    truncated,
                    QuicTransportParameterRole.Client,
                    out _));
            }
        }
    }

    private static QuicTransportParameters BuildRandomParameters(Random random)
    {
        QuicTransportParameters parameters = new()
        {
            OriginalDestinationConnectionId = RandomBytes(random, random.Next(0, 5)),
            MaxIdleTimeout = (ulong)random.Next(0, 4096),
            StatelessResetToken = RandomBytes(random, 16),
            MaxUdpPayloadSize = (ulong)random.Next(1200, 1600),
            InitialMaxData = (ulong)random.Next(0, 65536),
            InitialMaxStreamsBidi = (ulong)random.Next(0, 32),
            InitialMaxStreamsUni = (ulong)random.Next(0, 32),
            MaxAckDelay = (ulong)random.Next(0, 64),
            DisableActiveMigration = random.Next(0, 2) == 0,
            PreferredAddress = new QuicPreferredAddress
            {
                IPv4Address = RandomBytes(random, 4),
                IPv4Port = (ushort)random.Next(0, ushort.MaxValue + 1),
                IPv6Address = RandomBytes(random, 16),
                IPv6Port = (ushort)random.Next(0, ushort.MaxValue + 1),
                ConnectionId = RandomBytes(random, random.Next(1, 6)),
                StatelessResetToken = RandomBytes(random, 16),
            },
            ActiveConnectionIdLimit = (ulong)random.Next(2, 64),
            InitialSourceConnectionId = RandomBytes(random, random.Next(0, 5)),
            RetrySourceConnectionId = RandomBytes(random, random.Next(0, 5)),
        };

        return parameters;
    }

    private static byte[] RandomBytes(Random random, int length)
    {
        byte[] data = new byte[length];
        random.NextBytes(data);
        return data;
    }

    private static void AssertTransportParametersEqual(QuicTransportParameters expected, QuicTransportParameters actual)
    {
        Assert.True(expected.OriginalDestinationConnectionId!.AsSpan().SequenceEqual(actual.OriginalDestinationConnectionId!));
        Assert.Equal(expected.MaxIdleTimeout, actual.MaxIdleTimeout);
        Assert.True(expected.StatelessResetToken!.AsSpan().SequenceEqual(actual.StatelessResetToken!));
        Assert.Equal(expected.MaxUdpPayloadSize, actual.MaxUdpPayloadSize);
        Assert.Equal(expected.InitialMaxData, actual.InitialMaxData);
        Assert.Equal(expected.InitialMaxStreamsBidi, actual.InitialMaxStreamsBidi);
        Assert.Equal(expected.InitialMaxStreamsUni, actual.InitialMaxStreamsUni);
        Assert.Equal(expected.MaxAckDelay, actual.MaxAckDelay);
        Assert.Equal(expected.DisableActiveMigration, actual.DisableActiveMigration);
        Assert.NotNull(actual.PreferredAddress);
        Assert.True(expected.PreferredAddress!.IPv4Address.AsSpan().SequenceEqual(actual.PreferredAddress!.IPv4Address));
        Assert.Equal(expected.PreferredAddress.IPv4Port, actual.PreferredAddress.IPv4Port);
        Assert.True(expected.PreferredAddress.IPv6Address.AsSpan().SequenceEqual(actual.PreferredAddress.IPv6Address));
        Assert.Equal(expected.PreferredAddress.IPv6Port, actual.PreferredAddress.IPv6Port);
        Assert.True(expected.PreferredAddress.ConnectionId.AsSpan().SequenceEqual(actual.PreferredAddress.ConnectionId));
        Assert.True(expected.PreferredAddress.StatelessResetToken.AsSpan().SequenceEqual(actual.PreferredAddress.StatelessResetToken));
        Assert.Equal(expected.ActiveConnectionIdLimit, actual.ActiveConnectionIdLimit);
        Assert.True(expected.InitialSourceConnectionId!.AsSpan().SequenceEqual(actual.InitialSourceConnectionId!));
        Assert.True(expected.RetrySourceConnectionId!.AsSpan().SequenceEqual(actual.RetrySourceConnectionId!));
    }
}
