using System.Buffers.Binary;
using System.Linq;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0150")]
public sealed class REQ_QUIC_CRT_0150
{
    private const int HandshakeHeaderLength = 4;
    private const int UInt16Length = 2;
    private const int UInt24Length = 3;
    private const byte NewSessionTicketHandshakeType = 0x04;
    private const uint ExpectedTicketLifetimeSeconds = 600;
    private const int ExpectedTicketNonceLength = 8;
    private const int ExpectedTicketBytesLength = 32;

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EnabledServerPathPublishesOneRttNewSessionTicketCrypto()
    {
        QuicTlsTransportBridgeDriver driver =
            QuicPostHandshakeTicketTestSupport.CreateFinishedServerDriver(
                enableServerResumptionTickets: true,
                out IReadOnlyList<QuicTlsStateUpdate> finishedUpdates);

        QuicTlsStateUpdate ticketUpdate = Assert.Single(finishedUpdates, IsOneRttTicketUpdate);
        Assert.Equal(0UL, ticketUpdate.CryptoDataOffset);
        Assert.True(TryParseNewSessionTicket(ticketUpdate.CryptoData.Span, out ParsedNewSessionTicket parsedTicket));
        Assert.Equal(ExpectedTicketLifetimeSeconds, parsedTicket.LifetimeSeconds);
        Assert.Equal(ExpectedTicketNonceLength, parsedTicket.TicketNonce.Length);
        Assert.Equal(ExpectedTicketBytesLength, parsedTicket.TicketBytes.Length);
        Assert.Equal(0, parsedTicket.ExtensionsLength);
        Assert.Equal(ticketUpdate.CryptoData.Length, driver.State.OneRttEgressCryptoBuffer.BufferedBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RuntimeFlushesEnabledServerNewSessionTicketOnTheOneRttCryptoPath()
    {
        List<QuicConnectionEffect> baselineEffects = [];
        using QuicConnectionRuntime baselineRuntime =
            QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime(
                emittedEffects: baselineEffects,
                initializeActivePath: true);

        List<QuicConnectionEffect> ticketEffects = [];
        using QuicConnectionRuntime ticketRuntime =
            QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime(
                enableServerResumptionTickets: true,
                emittedEffects: ticketEffects,
                initializeActivePath: true);

        int baselineDatagrams = baselineEffects.OfType<QuicConnectionSendDatagramEffect>().Count();
        int ticketDatagrams = ticketEffects.OfType<QuicConnectionSendDatagramEffect>().Count();
        Assert.True(
            ticketDatagrams > baselineDatagrams,
            $"baseline={baselineDatagrams} ticket={ticketDatagrams} ticketEgress={ticketRuntime.TlsState.OneRttEgressCryptoBuffer.BufferedBytes} phase={ticketRuntime.Phase} oneRtt={ticketRuntime.TlsState.OneRttKeysAvailable}");
        Assert.Equal(0, ticketRuntime.TlsState.OneRttEgressCryptoBuffer.BufferedBytes);
        Assert.Equal(0, baselineRuntime.TlsState.OneRttEgressCryptoBuffer.BufferedBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DisabledServerPathDoesNotPublishOrBufferResumptionTickets()
    {
        QuicTlsTransportBridgeDriver driver =
            QuicPostHandshakeTicketTestSupport.CreateFinishedServerDriver(
                enableServerResumptionTickets: false,
                out IReadOnlyList<QuicTlsStateUpdate> finishedUpdates);

        Assert.DoesNotContain(finishedUpdates, IsOneRttTicketUpdate);
        Assert.Equal(0, driver.State.OneRttEgressCryptoBuffer.BufferedBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void FuzzEnabledServerTicketEmissionKeepsTheTicketShapeBounded()
    {
        for (int iteration = 0; iteration < 16; iteration++)
        {
            _ = QuicPostHandshakeTicketTestSupport.CreateFinishedServerDriver(
                enableServerResumptionTickets: true,
                out IReadOnlyList<QuicTlsStateUpdate> finishedUpdates);

            QuicTlsStateUpdate ticketUpdate = Assert.Single(finishedUpdates, IsOneRttTicketUpdate);
            Assert.True(TryParseNewSessionTicket(ticketUpdate.CryptoData.Span, out ParsedNewSessionTicket parsedTicket));
            Assert.Equal(ExpectedTicketLifetimeSeconds, parsedTicket.LifetimeSeconds);
            Assert.Equal(ExpectedTicketNonceLength, parsedTicket.TicketNonce.Length);
            Assert.Equal(ExpectedTicketBytesLength, parsedTicket.TicketBytes.Length);
            Assert.Equal(0, parsedTicket.ExtensionsLength);
        }
    }

    private static bool IsOneRttTicketUpdate(QuicTlsStateUpdate update)
    {
        return update.Kind == QuicTlsUpdateKind.CryptoDataAvailable
            && update.EncryptionLevel == QuicTlsEncryptionLevel.OneRtt
            && !update.CryptoData.IsEmpty;
    }

    private static bool TryParseNewSessionTicket(
        ReadOnlySpan<byte> message,
        out ParsedNewSessionTicket parsedTicket)
    {
        parsedTicket = default;

        if (message.Length < HandshakeHeaderLength
            || message[0] != NewSessionTicketHandshakeType)
        {
            return false;
        }

        int messageBodyLength = ReadUInt24(message.Slice(1, UInt24Length));
        if (messageBodyLength != message.Length - HandshakeHeaderLength)
        {
            return false;
        }

        int index = HandshakeHeaderLength;
        if (!TryReadUInt32(message, ref index, out uint lifetimeSeconds)
            || !TryReadUInt32(message, ref index, out uint ticketAgeAdd)
            || !TryReadUInt8(message, ref index, out int ticketNonceLength)
            || ticketNonceLength != ExpectedTicketNonceLength
            || index + ticketNonceLength > message.Length)
        {
            return false;
        }

        byte[] ticketNonce = message.Slice(index, ticketNonceLength).ToArray();
        index += ticketNonceLength;

        if (!TryReadUInt16(message, ref index, out ushort ticketLength)
            || ticketLength != ExpectedTicketBytesLength
            || index + ticketLength > message.Length)
        {
            return false;
        }

        byte[] ticketBytes = message.Slice(index, ticketLength).ToArray();
        index += ticketLength;

        if (!TryReadUInt16(message, ref index, out ushort extensionsLength)
            || index + extensionsLength != message.Length)
        {
            return false;
        }

        parsedTicket = new ParsedNewSessionTicket(
            lifetimeSeconds,
            ticketAgeAdd,
            ticketNonce,
            ticketBytes,
            extensionsLength);
        return true;
    }

    private static bool TryReadUInt8(ReadOnlySpan<byte> source, ref int index, out int value)
    {
        value = default;
        if (index >= source.Length)
        {
            return false;
        }

        value = source[index++];
        return true;
    }

    private static bool TryReadUInt16(ReadOnlySpan<byte> source, ref int index, out ushort value)
    {
        value = default;
        if (index > source.Length - UInt16Length)
        {
            return false;
        }

        value = BinaryPrimitives.ReadUInt16BigEndian(source.Slice(index, UInt16Length));
        index += UInt16Length;
        return true;
    }

    private static bool TryReadUInt32(ReadOnlySpan<byte> source, ref int index, out uint value)
    {
        value = default;
        if (index > source.Length - sizeof(uint))
        {
            return false;
        }

        value = BinaryPrimitives.ReadUInt32BigEndian(source.Slice(index, sizeof(uint)));
        index += sizeof(uint);
        return true;
    }

    private static int ReadUInt24(ReadOnlySpan<byte> source)
    {
        return (source[0] << 16) | (source[1] << 8) | source[2];
    }

    private readonly record struct ParsedNewSessionTicket(
        uint LifetimeSeconds,
        uint TicketAgeAdd,
        byte[] TicketNonce,
        byte[] TicketBytes,
        ushort ExtensionsLength);
}
