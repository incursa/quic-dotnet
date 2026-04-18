using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks transport-parameter parsing and formatting.
/// </summary>
[MemoryDiagnoser]
public class QuicTransportParametersBenchmarks
{
    public enum TransportParameterBenchmarkScenario
    {
        ServerBaseline = 0,
        ServerLarge = 1,
        ClientVariant = 2,
        ClientMinimal = 3,
        ServerBoundary = 4,
    }

    [Params(
        TransportParameterBenchmarkScenario.ServerBaseline,
        TransportParameterBenchmarkScenario.ServerLarge,
        TransportParameterBenchmarkScenario.ClientVariant,
        TransportParameterBenchmarkScenario.ClientMinimal,
        TransportParameterBenchmarkScenario.ServerBoundary)]
    public TransportParameterBenchmarkScenario Scenario { get; set; }

    private const ulong BoundaryVarintValue = 1UL << 60;

    private QuicTransportParameters parameters = new();
    private byte[] encoded = [];
    private byte[] destination = [];
    private QuicTransportParameterRole senderRole;
    private QuicTransportParameterRole receiverRole;

    /// <summary>
    /// Prepares representative transport parameters and their encoded form.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        (parameters, senderRole, receiverRole) = Scenario switch
        {
            TransportParameterBenchmarkScenario.ServerBaseline => (
                CreateBaselineTransportParameters(),
                QuicTransportParameterRole.Server,
                QuicTransportParameterRole.Client),
            TransportParameterBenchmarkScenario.ServerLarge => (
                CreateServerLargeTransportParameters(),
                QuicTransportParameterRole.Server,
                QuicTransportParameterRole.Client),
            TransportParameterBenchmarkScenario.ClientVariant => (
                CreateBaselineTransportParameters(),
                QuicTransportParameterRole.Client,
                QuicTransportParameterRole.Server),
            TransportParameterBenchmarkScenario.ClientMinimal => (
                CreateMinimalClientTransportParameters(),
                QuicTransportParameterRole.Client,
                QuicTransportParameterRole.Server),
            TransportParameterBenchmarkScenario.ServerBoundary => (
                CreateBoundaryTransportParameters(),
                QuicTransportParameterRole.Server,
                QuicTransportParameterRole.Client),
            _ => throw new InvalidOperationException($"Unsupported transport-parameter benchmark scenario: {Scenario}."),
        };

        destination = new byte[1024];
        if (!QuicTransportParametersCodec.TryFormatTransportParameters(
                parameters,
                senderRole,
                destination,
                out int bytesWritten))
        {
            throw new InvalidOperationException("Failed to prepare transport-parameter benchmark input.");
        }

        encoded = destination[..bytesWritten].ToArray();
    }

    /// <summary>
    /// Measures transport-parameter parsing.
    /// </summary>
    [Benchmark]
    public int ParseTransportParameters()
    {
        return QuicTransportParametersCodec.TryParseTransportParameters(
            encoded,
            receiverRole,
            out QuicTransportParameters parsed)
            ? (int)(parsed.InitialMaxData ?? 0)
            : -1;
    }

    /// <summary>
    /// Measures transport-parameter formatting.
    /// </summary>
    [Benchmark]
    public int FormatTransportParameters()
    {
        return QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            senderRole,
            destination,
            out int bytesWritten)
            ? bytesWritten
            : -1;
    }

    private static QuicTransportParameters CreateBaselineTransportParameters()
    {
        return new QuicTransportParameters
        {
            MaxIdleTimeout = 25,
            MaxUdpPayloadSize = 1200,
            InitialMaxData = 4096,
            InitialMaxStreamDataBidiLocal = 2048,
            InitialMaxStreamDataBidiRemote = 4096,
            InitialMaxStreamDataUni = 1024,
            InitialMaxStreamsBidi = 6,
            InitialMaxStreamsUni = 7,
            MaxAckDelay = 33,
            DisableActiveMigration = true,
            ActiveConnectionIdLimit = 8,
            InitialSourceConnectionId = [0x11, 0x22],
        };
    }

    private static QuicTransportParameters CreateServerLargeTransportParameters()
    {
        return new QuicTransportParameters
        {
            OriginalDestinationConnectionId = CreateSequentialBytes(0x10, 4),
            MaxIdleTimeout = 120,
            StatelessResetToken = CreateSequentialBytes(0x20, 16),
            MaxUdpPayloadSize = 1350,
            InitialMaxData = 65_535,
            InitialMaxStreamDataBidiLocal = 32_768,
            InitialMaxStreamDataBidiRemote = 65_535,
            InitialMaxStreamDataUni = 16_384,
            InitialMaxStreamsBidi = 24,
            InitialMaxStreamsUni = 20,
            MaxAckDelay = 50,
            DisableActiveMigration = true,
            PreferredAddress = new QuicPreferredAddress
            {
                IPv4Address = [192, 0, 2, 10],
                IPv4Port = 9_443,
                IPv6Address = CreateSequentialBytes(0x30, 16),
                IPv6Port = 9_553,
                ConnectionId = CreateSequentialBytes(0x40, 20),
                StatelessResetToken = CreateSequentialBytes(0x60, 16),
            },
            ActiveConnectionIdLimit = 16,
            InitialSourceConnectionId = CreateSequentialBytes(0x50, 8),
            RetrySourceConnectionId = CreateSequentialBytes(0x70, 6),
        };
    }

    private static QuicTransportParameters CreateMinimalClientTransportParameters()
    {
        return new QuicTransportParameters
        {
            ActiveConnectionIdLimit = 2,
            InitialSourceConnectionId = [0x01],
        };
    }

    private static QuicTransportParameters CreateBoundaryTransportParameters()
    {
        return new QuicTransportParameters
        {
            OriginalDestinationConnectionId = CreateSequentialBytes(0x10, 20),
            MaxIdleTimeout = BoundaryVarintValue,
            StatelessResetToken = CreateSequentialBytes(0x20, 16),
            MaxUdpPayloadSize = BoundaryVarintValue,
            InitialMaxData = BoundaryVarintValue,
            InitialMaxStreamDataBidiLocal = BoundaryVarintValue,
            InitialMaxStreamDataBidiRemote = BoundaryVarintValue,
            InitialMaxStreamDataUni = BoundaryVarintValue,
            InitialMaxStreamsBidi = BoundaryVarintValue,
            InitialMaxStreamsUni = BoundaryVarintValue,
            MaxAckDelay = BoundaryVarintValue,
            DisableActiveMigration = true,
            PreferredAddress = new QuicPreferredAddress
            {
                IPv4Address = [198, 51, 100, 1],
                IPv4Port = 65_535,
                IPv6Address = CreateSequentialBytes(0x30, 16),
                IPv6Port = 65_534,
                ConnectionId = CreateSequentialBytes(0x40, 20),
                StatelessResetToken = CreateSequentialBytes(0x60, 16),
            },
            ActiveConnectionIdLimit = BoundaryVarintValue,
            InitialSourceConnectionId = CreateSequentialBytes(0x50, 20),
            RetrySourceConnectionId = CreateSequentialBytes(0x70, 20),
        };
    }

    private static byte[] CreateSequentialBytes(byte startValue, int length)
    {
        byte[] bytes = new byte[length];
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = unchecked((byte)(startValue + i));
        }

        return bytes;
    }
}
