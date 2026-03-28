using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks the hot header parsing paths for version-independent QUIC packet views.
/// </summary>
[MemoryDiagnoser]
public class QuicHeaderParsingBenchmarks
{
    private byte[] longHeader = [];
    private byte[] shortHeader = [];
    private byte[] versionNegotiationHeader = [];

    /// <summary>
    /// Prepares representative packet buffers for the benchmarks.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        shortHeader = new byte[]
        {
            0x40,
            0x11,
            0x22,
            0x33,
            0x44,
            0x55,
            0x66,
            0x77,
            0x88,
        };

        longHeader = new byte[]
        {
            0xC3,
            0x00,
            0x00,
            0x00,
            0x01,
            0x04,
            0x11,
            0x22,
            0x33,
            0x44,
            0x04,
            0x55,
            0x66,
            0x77,
            0x88,
            0x99,
            0xAA,
        };

        versionNegotiationHeader = new byte[]
        {
            0xC1,
            0x00,
            0x00,
            0x00,
            0x00,
            0x04,
            0x11,
            0x22,
            0x33,
            0x44,
            0x04,
            0x55,
            0x66,
            0x77,
            0x88,
            0x00,
            0x00,
            0x00,
            0x01,
            0x00,
            0x00,
            0x00,
            0x02,
        };
    }

    /// <summary>
    /// Measures short-header classification.
    /// </summary>
    [Benchmark]
    public int ClassifyShortHeader()
    {
        return QuicPacketParser.TryClassifyHeaderForm(shortHeader, out QuicHeaderForm headerForm)
            ? (int)headerForm
            : -1;
    }

    /// <summary>
    /// Measures long-header classification.
    /// </summary>
    [Benchmark]
    public int ClassifyLongHeader()
    {
        return QuicPacketParser.TryClassifyHeaderForm(longHeader, out QuicHeaderForm headerForm)
            ? (int)headerForm
            : -1;
    }

    /// <summary>
    /// Measures long-header parsing.
    /// </summary>
    [Benchmark]
    public int ParseLongHeader()
    {
        return QuicPacketParser.TryParseLongHeader(longHeader, out QuicLongHeaderPacket header)
            ? header.DestinationConnectionIdLength + header.SourceConnectionIdLength + header.VersionSpecificData.Length
            : -1;
    }

    /// <summary>
    /// Measures Version Negotiation parsing.
    /// </summary>
    [Benchmark]
    public int ParseVersionNegotiation()
    {
        return QuicPacketParser.TryParseVersionNegotiation(versionNegotiationHeader, out QuicVersionNegotiationPacket header)
            ? header.SupportedVersionCount
            : -1;
    }

    /// <summary>
    /// Measures short-header parsing with an opaque remainder.
    /// </summary>
    [Benchmark]
    public int ParseShortHeader()
    {
        return QuicPacketParser.TryParseShortHeader(shortHeader, out QuicShortHeaderPacket header)
            ? header.Remainder.Length
            : -1;
    }
}
