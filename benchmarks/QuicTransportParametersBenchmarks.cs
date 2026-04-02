using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks transport-parameter parsing and formatting.
/// </summary>
[MemoryDiagnoser]
public class QuicTransportParametersBenchmarks
{
    private QuicTransportParameters parameters = new();
    private byte[] encoded = [];
    private byte[] destination = [];

    /// <summary>
    /// Prepares representative transport parameters and their encoded form.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        parameters = new QuicTransportParameters
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

        destination = new byte[256];
        if (!QuicTransportParametersCodec.TryFormatTransportParameters(
                parameters,
                QuicTransportParameterRole.Server,
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
            QuicTransportParameterRole.Client,
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
            QuicTransportParameterRole.Server,
            destination,
            out int bytesWritten)
            ? bytesWritten
            : -1;
    }
}
