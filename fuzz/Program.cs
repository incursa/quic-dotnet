// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Incursa.Quic;
using Incursa.Quic.Http3;
using SharpFuzz;

namespace Incursa.Quic.Fuzz;

public static class Program
{
    public static void Main(string[] args)
    {
        Fuzzer.Run(ConsumeInput);
    }

    private static void ConsumeInput(Stream stream)
    {
        using MemoryStream buffer = new();
        stream.CopyTo(buffer);

        ReadOnlySpan<byte> packet = buffer.GetBuffer().AsSpan(0, checked((int)buffer.Length));

        QuicVariableLengthInteger.TryParse(packet, out _, out _);
        QuicStreamParser.TryParseStreamIdentifier(packet, out _, out _);
        QuicStreamParser.TryParseStreamFrame(packet, out _);

        QuicPacketParser.TryClassifyHeaderForm(packet, out _);
        QuicPacketParser.TryParseLongHeader(packet, out _);
        QuicPacketParser.TryParseShortHeader(packet, out _);
        QuicPacketParser.TryParseVersionNegotiation(packet, out _);

        TryReadWebSocketMessages(packet, Http3EndpointRole.Client);
        TryReadWebSocketMessages(packet, Http3EndpointRole.Server);
    }

    private static void TryReadWebSocketMessages(ReadOnlySpan<byte> packet, Http3EndpointRole receivingEndpointRole)
    {
        try
        {
            Http3WebSocketMessageReader reader = new(receivingEndpointRole);
            reader.Read(packet, endOfStream: true);
        }
        catch (Http3Exception exception)
        {
            ConsumeExpectedFuzzException(exception);
        }
        catch (ArgumentException exception)
        {
            ConsumeExpectedFuzzException(exception);
        }
        catch (OverflowException exception)
        {
            ConsumeExpectedFuzzException(exception);
        }
    }

    private static void ConsumeExpectedFuzzException(Exception exception)
    {
        _ = exception.Message;
    }
}
