// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

internal static class QuicVersionInformationFuzzSupport
{
    public static void FuzzTransportParameterCodecRoundTripsVersionInformationAcrossRepresentativeVersionSets()
    {
        Random random = new(0x5150_9368);
        Span<byte> destination = stackalloc byte[512];

        for (int iteration = 0; iteration < 64; iteration++)
        {
            bool clientRole = (iteration & 1) == 0;
            QuicTransportParameters parameters = BuildRandomTransportParameters(random, clientRole);

            Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
                parameters,
                clientRole ? QuicTransportParameterRole.Client : QuicTransportParameterRole.Server,
                destination,
                out int bytesWritten));

            Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
                destination[..bytesWritten],
                clientRole ? QuicTransportParameterRole.Server : QuicTransportParameterRole.Client,
                out QuicTransportParameters parsed));

            Assert.NotNull(parsed.VersionInformation);
            AssertVersionInformationEqual(parameters.VersionInformation!, parsed.VersionInformation!);
        }
    }

    public static void FuzzTransportParameterCodecRejectsMalformedVersionInformationAcrossRepresentativeShapes()
    {
        Random random = new(0x5150_9369);

        for (int iteration = 0; iteration < 64; iteration++)
        {
            byte[] encoded = iteration switch
            {
                0 => BuildMalformedVersionInformationBlock([QuicTransportParameterTestData.BuildTransportParameterTuple(0x11, [0x00, 0x00, 0x00, 0x00])]),
                1 => BuildMalformedVersionInformationBlock([QuicTransportParameterTestData.BuildTransportParameterTuple(0x11, [0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00])]),
                2 => BuildMalformedVersionInformationBlock([QuicTransportParameterTestData.BuildTransportParameterTuple(0x11, [0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00])]),
                3 => BuildMalformedVersionInformationBlock([QuicTransportParameterTestData.BuildTransportParameterTuple(0x11, [0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01])]),
                _ => BuildMalformedVersionInformationBlock(BuildRandomInvalidTuples(random)),
            };

            Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
                encoded,
                QuicTransportParameterRole.Server,
                out _));
        }
    }

    private static QuicTransportParameters BuildRandomTransportParameters(Random random, bool clientRole)
    {
        uint chosenVersion = (random.Next(0, 2) == 0)
            ? QuicVersionNegotiation.Version1
            : QuicVersionNegotiation.Version2;

        uint[] availableVersions =
        [
            chosenVersion,
            QuicVersionNegotiation.Version1 == chosenVersion
                ? QuicVersionNegotiation.Version2
                : QuicVersionNegotiation.Version1,
            QuicVersionNegotiation.CreateReservedVersion((uint)random.NextInt64(0x10000000, 0x7FFFFFFF)),
        ];

        if (!clientRole)
        {
            availableVersions = random.Next(0, 2) == 0
                ? []
                : availableVersions;
        }

        return new QuicTransportParameters
        {
            GreaseQuicBit = random.Next(0, 2) == 0,
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
            VersionInformation = new QuicVersionInformation
            {
                ChosenVersion = chosenVersion,
                AvailableVersions = availableVersions,
            },
        };
    }

    private static byte[] BuildMalformedVersionInformationBlock(byte[][] versionInformationTuples)
    {
        return QuicTransportParameterTestData.BuildTransportParameterBlock(versionInformationTuples);
    }

    private static byte[][] BuildRandomInvalidTuples(Random random)
    {
        List<byte[]> tuples = [];

        tuples.Add(QuicTransportParameterTestData.BuildTransportParameterTuple(
            0x11,
            BuildRandomMalformedVersionInformationValue(random)));

        if (random.Next(0, 2) == 0)
        {
            tuples.Add(QuicTransportParameterTestData.BuildTransportParameterTuple(
                0x01,
                QuicVarintTestData.EncodeMinimal((ulong)random.Next(0, 1024))));
        }

        if (random.Next(0, 2) == 0)
        {
            tuples.Add(QuicTransportParameterTestData.BuildTransportParameterTuple(
                0x0E,
                QuicVarintTestData.EncodeMinimal((ulong)random.Next(2, 16))));
        }

        return tuples.ToArray();
    }

    private static byte[] BuildRandomMalformedVersionInformationValue(Random random)
    {
        return random.Next(0, 4) switch
        {
            0 => [0x00, 0x00, 0x00, 0x00],
            1 => [0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
            2 => [0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00],
            _ => [0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01],
        };
    }

    private static void AssertVersionInformationEqual(QuicVersionInformation expected, QuicVersionInformation actual)
    {
        Assert.Equal(expected.ChosenVersion, actual.ChosenVersion);
        Assert.True(expected.AvailableVersions.AsSpan().SequenceEqual(actual.AvailableVersions));
    }

    private static byte[] RandomBytes(Random random, int length)
    {
        byte[] bytes = new byte[length];
        random.NextBytes(bytes);
        return bytes;
    }
}
