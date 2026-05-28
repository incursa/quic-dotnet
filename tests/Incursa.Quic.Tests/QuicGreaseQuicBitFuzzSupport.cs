// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

internal static class QuicGreaseQuicBitFuzzSupport
{
    public static void FuzzTransportParameterCodecRoundTripsAndValidatesGreaseBit()
    {
        Random random = new(0x5150_9287);
        Span<byte> destination = stackalloc byte[512];
        byte[] greaseTuple = QuicTransportParameterTestData.BuildTransportParameterTuple(0x2AB2, []);

        for (int iteration = 0; iteration < 64; iteration++)
        {
            bool greaseEnabled = (iteration & 1) == 0;
            QuicTransportParameters parameters = BuildRandomClientTransportParameters(random, greaseEnabled);

            Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
                parameters,
                QuicTransportParameterRole.Client,
                destination,
                out int bytesWritten));

            ReadOnlySpan<byte> encoded = destination[..bytesWritten];
            if (greaseEnabled)
            {
                Assert.True(ContainsSubsequence(encoded, greaseTuple));
            }

            Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
                encoded,
                QuicTransportParameterRole.Server,
                out QuicTransportParameters parsed));

            Assert.Equal(greaseEnabled, parsed.GreaseQuicBit);
            Assert.Equal(parameters.MaxIdleTimeout, parsed.MaxIdleTimeout);
            Assert.Equal(parameters.MaxUdpPayloadSize, parsed.MaxUdpPayloadSize);
            Assert.Equal(parameters.InitialMaxData, parsed.InitialMaxData);
            Assert.Equal(parameters.InitialMaxStreamsBidi, parsed.InitialMaxStreamsBidi);
            Assert.Equal(parameters.InitialMaxStreamsUni, parsed.InitialMaxStreamsUni);
            Assert.Equal(parameters.ActiveConnectionIdLimit, parsed.ActiveConnectionIdLimit);
            Assert.True(parameters.InitialSourceConnectionId!.AsSpan().SequenceEqual(parsed.InitialSourceConnectionId!));
        }
    }

    public static void FuzzTransportParameterCodecRejectsNonEmptyGreaseBitValues()
    {
        Random random = new(0x5150_9288);

        for (int iteration = 0; iteration < 64; iteration++)
        {
            List<byte[]> tuples = BuildRandomClientTransportParameterTuples(random);
            byte[] greaseTuple = QuicTransportParameterTestData.BuildTransportParameterTuple(
                0x2AB2,
                RandomBytes(random, random.Next(1, 5)));

            tuples.Insert(random.Next(0, tuples.Count + 1), greaseTuple);

            byte[] encoded = QuicTransportParameterTestData.BuildTransportParameterBlock(tuples.ToArray());

            Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
                encoded,
                QuicTransportParameterRole.Server,
                out _));
        }
    }

    public static void FuzzGreasedPacketAcceptancePolicy()
    {
        Random random = new(0x5150_9289);
        using QuicConnectionRuntime senderRuntime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();

        senderRuntime.TlsState.LocalTransportParameters!.GreaseQuicBit = true;
        senderRuntime.TlsState.PeerTransportParameters!.GreaseQuicBit = true;

        QuicHandshakeFlowCoordinator senderCoordinator = senderRuntime.HandshakeFlowCoordinator;

        for (int iteration = 0; iteration < 32; iteration++)
        {
            ReadOnlySpan<byte> applicationPayload = RandomBytes(random, random.Next(0, 33));

            Assert.True(senderCoordinator.TryBuildProtectedApplicationDataPacket(
                applicationPayload,
                senderRuntime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
                senderRuntime.TlsState.CurrentOneRttKeyPhaseBit,
                spinBit: false,
                greaseQuicBit: true,
                out ulong packetNumber,
                out byte[] protectedPacket));

            Assert.True(senderCoordinator.TryOpenProtectedApplicationDataPacket(
                protectedPacket,
                senderRuntime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
                packetNumber,
                allowClearedFixedBit: true,
                out byte[] openedPacket,
                out int payloadOffset,
                out int payloadLength,
                out bool keyPhase));

            Assert.Equal(senderRuntime.TlsState.CurrentOneRttKeyPhaseBit, keyPhase);
            Assert.Equal(0, openedPacket[0] & QuicPacketHeaderBits.FixedBitMask);
            Assert.True(applicationPayload.SequenceEqual(openedPacket.AsSpan(payloadOffset, applicationPayload.Length)));
            Assert.True(openedPacket.AsSpan(
                payloadOffset + applicationPayload.Length,
                payloadLength - applicationPayload.Length).SequenceEqual(new byte[payloadLength - applicationPayload.Length]));

            Assert.False(senderCoordinator.TryOpenProtectedApplicationDataPacket(
                protectedPacket,
                senderRuntime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
                packetNumber,
                allowClearedFixedBit: false,
                out _,
                out _,
                out _,
                out _));
        }
    }

    public static void FuzzGreasedPacketTransmissionPolicy()
    {
        Random random = new(0x5150_928A);
        using QuicConnectionRuntime senderRuntime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();

        senderRuntime.TlsState.LocalTransportParameters!.GreaseQuicBit = true;
        senderRuntime.TlsState.PeerTransportParameters!.GreaseQuicBit = true;

        QuicHandshakeFlowCoordinator senderCoordinator = senderRuntime.HandshakeFlowCoordinator;

        for (int iteration = 0; iteration < 32; iteration++)
        {
            ReadOnlySpan<byte> applicationPayload = RandomBytes(random, random.Next(0, 33));

            Assert.True(senderCoordinator.TryBuildProtectedApplicationDataPacket(
                applicationPayload,
                senderRuntime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
                senderRuntime.TlsState.CurrentOneRttKeyPhaseBit,
                spinBit: false,
                greaseQuicBit: true,
                out _,
                out byte[] greasedPacket));

            Assert.Equal(0, greasedPacket[0] & QuicPacketHeaderBits.FixedBitMask);

            Assert.True(senderCoordinator.TryBuildProtectedApplicationDataPacket(
                applicationPayload,
                senderRuntime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
                senderRuntime.TlsState.CurrentOneRttKeyPhaseBit,
                spinBit: false,
                greaseQuicBit: false,
                out _,
                out byte[] strictPacket));

            Assert.Equal(QuicPacketHeaderBits.FixedBitMask, strictPacket[0] & QuicPacketHeaderBits.FixedBitMask);
        }
    }

    private static QuicTransportParameters BuildRandomClientTransportParameters(Random random, bool greaseEnabled)
    {
        return new QuicTransportParameters
        {
            GreaseQuicBit = greaseEnabled,
            MaxIdleTimeout = (ulong)random.Next(0, 1024),
            MaxUdpPayloadSize = (ulong)random.Next(1200, 1501),
            InitialMaxData = (ulong)random.Next(0, 1 << 20),
            InitialMaxStreamDataBidiLocal = (ulong)random.Next(0, 1 << 20),
            InitialMaxStreamDataBidiRemote = (ulong)random.Next(0, 1 << 20),
            InitialMaxStreamDataUni = (ulong)random.Next(0, 1 << 20),
            InitialMaxStreamsBidi = (ulong)random.Next(0, 64),
            InitialMaxStreamsUni = (ulong)random.Next(0, 64),
            MaxAckDelay = (ulong)random.Next(0, 256),
            DisableActiveMigration = random.Next(0, 2) == 0,
            ActiveConnectionIdLimit = (ulong)random.Next(2, 16),
            InitialSourceConnectionId = RandomBytes(random, random.Next(1, 9)),
        };
    }

    private static List<byte[]> BuildRandomClientTransportParameterTuples(Random random)
    {
        List<byte[]> tuples = [];

        if (random.Next(0, 2) == 0)
        {
            tuples.Add(QuicTransportParameterTestData.BuildTransportParameterTuple(0x01, QuicVarintTestData.EncodeMinimal((ulong)random.Next(0, 1024))));
        }

        if (random.Next(0, 2) == 0)
        {
            tuples.Add(QuicTransportParameterTestData.BuildTransportParameterTuple(0x03, QuicVarintTestData.EncodeMinimal((ulong)random.Next(1200, 1501))));
        }

        if (random.Next(0, 2) == 0)
        {
            tuples.Add(QuicTransportParameterTestData.BuildTransportParameterTuple(0x04, QuicVarintTestData.EncodeMinimal((ulong)random.Next(0, 1 << 20))));
        }

        if (random.Next(0, 2) == 0)
        {
            tuples.Add(QuicTransportParameterTestData.BuildTransportParameterTuple(0x05, QuicVarintTestData.EncodeMinimal((ulong)random.Next(0, 1 << 20))));
        }

        if (random.Next(0, 2) == 0)
        {
            tuples.Add(QuicTransportParameterTestData.BuildTransportParameterTuple(0x06, QuicVarintTestData.EncodeMinimal((ulong)random.Next(0, 1 << 20))));
        }

        if (random.Next(0, 2) == 0)
        {
            tuples.Add(QuicTransportParameterTestData.BuildTransportParameterTuple(0x07, QuicVarintTestData.EncodeMinimal((ulong)random.Next(0, 1 << 20))));
        }

        if (random.Next(0, 2) == 0)
        {
            tuples.Add(QuicTransportParameterTestData.BuildTransportParameterTuple(0x08, QuicVarintTestData.EncodeMinimal((ulong)random.Next(0, 64))));
        }

        if (random.Next(0, 2) == 0)
        {
            tuples.Add(QuicTransportParameterTestData.BuildTransportParameterTuple(0x09, QuicVarintTestData.EncodeMinimal((ulong)random.Next(0, 64))));
        }

        if (random.Next(0, 2) == 0)
        {
            tuples.Add(QuicTransportParameterTestData.BuildTransportParameterTuple(0x0B, QuicVarintTestData.EncodeMinimal((ulong)random.Next(0, 256))));
        }

        tuples.Add(QuicTransportParameterTestData.BuildTransportParameterTuple(0x0F, RandomBytes(random, random.Next(1, 9))));

        return tuples;
    }

    private static bool ContainsSubsequence(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle)
    {
        if (needle.IsEmpty)
        {
            return true;
        }

        if (needle.Length > haystack.Length)
        {
            return false;
        }

        for (int offset = 0; offset <= haystack.Length - needle.Length; offset++)
        {
            if (haystack.Slice(offset, needle.Length).SequenceEqual(needle))
            {
                return true;
            }
        }

        return false;
    }

    private static byte[] RandomBytes(Random random, int length)
    {
        byte[] data = new byte[length];
        random.NextBytes(data);
        return data;
    }
}
