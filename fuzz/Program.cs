// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Incursa.Quic;
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
    }
}
