using System.Buffers.Binary;
using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks the hot header parsing paths for version-independent QUIC packet views.
/// </summary>
[MemoryDiagnoser]
public class QuicHeaderParsingBenchmarks
{
    private byte[] longHeader = [];
    private byte[] longHeaderLargePayload = [];
    private byte[] shortHeader = [];
    private byte[] truncatedLongHeader = [];
    private byte[] versionNegotiationHeader = [];
    private byte[] versionNegotiationDestination = [];
    private byte[] versionNegotiationClientDestinationConnectionId = [];
    private byte[] versionNegotiationClientSourceConnectionId = [];
    private uint[] versionNegotiationSupportedVersions = [];
    private uint[] versionNegotiationSupportedVersionsExpanded = [];

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

        versionNegotiationClientDestinationConnectionId = [0x11, 0x22, 0x33, 0x44];
        versionNegotiationClientSourceConnectionId = [0x55, 0x66, 0x77, 0x88];
        versionNegotiationSupportedVersions =
        [
            QuicVersionNegotiation.Version1,
            QuicVersionNegotiation.CreateReservedVersion(0x10203040),
        ];
        longHeaderLargePayload = BuildLongHeader(
            headerControlBits: 0x63,
            version: QuicVersionNegotiation.Version1,
            destinationConnectionId: BuildSequentialBytes(20, 0x11),
            sourceConnectionId: BuildSequentialBytes(20, 0x31),
            versionSpecificData: BuildHandshakeVersionSpecificData(96));
        truncatedLongHeader = longHeaderLargePayload[..^1];
        versionNegotiationSupportedVersionsExpanded =
        [
            QuicVersionNegotiation.Version1,
            QuicVersionNegotiation.CreateReservedVersion(0x10203040),
            QuicVersionNegotiation.CreateReservedVersion(0x50607080),
            QuicVersionNegotiation.CreateReservedVersion(0x90A0B0C0),
            QuicVersionNegotiation.CreateReservedVersion(0xD0E0F000),
            QuicVersionNegotiation.CreateReservedVersion(0x11121314),
            QuicVersionNegotiation.CreateReservedVersion(0x21222324),
            QuicVersionNegotiation.CreateReservedVersion(0x31323334),
        ];
        versionNegotiationDestination = new byte[64];
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
    /// Measures long-header parsing on a larger valid payload.
    /// </summary>
    [Benchmark]
    public int ParseLongHeaderLargePayload()
    {
        return QuicPacketParser.TryParseLongHeader(longHeaderLargePayload, out QuicLongHeaderPacket header)
            ? header.DestinationConnectionIdLength + header.SourceConnectionIdLength + header.VersionSpecificData.Length
            : -1;
    }

    /// <summary>
    /// Measures the truncated long-header failure path after the parser has walked the header fields.
    /// </summary>
    [Benchmark]
    public int ParseTruncatedLongHeaderLargePayload()
    {
        return QuicPacketParser.TryParseLongHeader(truncatedLongHeader, out QuicLongHeaderPacket header)
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

    /// <summary>
    /// Measures Version Negotiation response formatting.
    /// </summary>
    [Benchmark]
    public int FormatVersionNegotiationResponse()
    {
        return QuicVersionNegotiation.TryFormatVersionNegotiationResponse(
            clientSelectedVersion: 0xA0B0C0D0,
            versionNegotiationClientDestinationConnectionId,
            versionNegotiationClientSourceConnectionId,
            versionNegotiationSupportedVersions,
            versionNegotiationDestination,
            out int bytesWritten)
            ? bytesWritten
            : -1;
    }

    /// <summary>
    /// Measures Version Negotiation formatting with a longer advertised version list.
    /// </summary>
    [Benchmark]
    public int FormatVersionNegotiationResponseWithExpandedSupportedVersions()
    {
        return QuicVersionNegotiation.TryFormatVersionNegotiationResponse(
            clientSelectedVersion: 0xA0B0C0D0,
            versionNegotiationClientDestinationConnectionId,
            versionNegotiationClientSourceConnectionId,
            versionNegotiationSupportedVersionsExpanded,
            versionNegotiationDestination,
            out int bytesWritten)
            ? bytesWritten
            : -1;
    }

    private static byte[] BuildLongHeader(
        byte headerControlBits,
        uint version,
        ReadOnlySpan<byte> destinationConnectionId,
        ReadOnlySpan<byte> sourceConnectionId,
        ReadOnlySpan<byte> versionSpecificData)
    {
        byte[] packet = new byte[1 + sizeof(uint) + 1 + destinationConnectionId.Length + 1 + sourceConnectionId.Length + versionSpecificData.Length];
        packet[0] = (byte)(0x80 | (headerControlBits & 0x7F));
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(1, sizeof(uint)), version);
        packet[5] = (byte)destinationConnectionId.Length;
        destinationConnectionId.CopyTo(packet.AsSpan(6, destinationConnectionId.Length));

        int sourceConnectionIdLengthOffset = 6 + destinationConnectionId.Length;
        packet[sourceConnectionIdLengthOffset] = (byte)sourceConnectionId.Length;
        sourceConnectionId.CopyTo(packet.AsSpan(sourceConnectionIdLengthOffset + 1, sourceConnectionId.Length));
        versionSpecificData.CopyTo(packet.AsSpan(sourceConnectionIdLengthOffset + 1 + sourceConnectionId.Length, versionSpecificData.Length));

        return packet;
    }

    private static byte[] BuildSequentialBytes(int length, byte startValue)
    {
        byte[] bytes = new byte[length];
        for (int index = 0; index < bytes.Length; index++)
        {
            bytes[index] = unchecked((byte)(startValue + index));
        }

        return bytes;
    }

    private static byte[] BuildHandshakeVersionSpecificData(int protectedPayloadLength)
    {
        const int packetNumberLength = 4;
        Span<byte> payloadLengthBuffer = stackalloc byte[QuicVariableLengthInteger.MaxEncodedLength];
        if (!QuicVariableLengthInteger.TryFormat((ulong)(packetNumberLength + protectedPayloadLength), payloadLengthBuffer, out int payloadLengthBytes))
        {
            throw new System.InvalidOperationException("Unable to encode the handshake payload length.");
        }

        byte[] versionSpecificData = new byte[payloadLengthBytes + packetNumberLength + protectedPayloadLength];
        int offset = 0;
        payloadLengthBuffer[..payloadLengthBytes].CopyTo(versionSpecificData.AsSpan(offset));
        offset += payloadLengthBytes;

        for (int index = 0; index < packetNumberLength; index++)
        {
            versionSpecificData[offset + index] = (byte)(0x90 + index);
        }

        offset += packetNumberLength;

        for (int index = 0; index < protectedPayloadLength; index++)
        {
            versionSpecificData[offset + index] = (byte)(0xA0 + index);
        }

        return versionSpecificData;
    }
}
