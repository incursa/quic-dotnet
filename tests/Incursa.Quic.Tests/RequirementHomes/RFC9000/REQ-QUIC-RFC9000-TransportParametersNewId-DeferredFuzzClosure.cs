// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_TransportParametersNewId_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1100")]
    [Requirement("REQ-QUIC-RFC9000-1145")]
    [Requirement("REQ-QUIC-RFC9000-1146")]
    [Requirement("REQ-QUIC-RFC9000-1147")]
    [Requirement("REQ-QUIC-RFC9000-1151")]
    [Requirement("REQ-QUIC-RFC9000-1154")]
    [Requirement("REQ-QUIC-RFC9000-1157")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ServerTransportParameterExtensionDataRoundTripsPreferredAddressCases()
    {
        foreach (PreferredAddressCase testCase in PreferredAddressCases())
        {
            QuicTransportParameters parameters = new()
            {
                InitialSourceConnectionId = testCase.InitialSourceConnectionId,
                PreferredAddress = testCase.PreferredAddress,
                ActiveConnectionIdLimit = testCase.ActiveConnectionIdLimit,
            };

            byte[] encoded = new byte[256];
            Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
                parameters,
                QuicTransportParameterRole.Server,
                encoded,
                out int bytesWritten));

            byte[] exactEncoded = encoded[..bytesWritten];
            byte[] expectedPreferredAddressValue = QuicTransportParameterTestData.BuildPreferredAddressValue(
                testCase.PreferredAddress.IPv4Address,
                testCase.PreferredAddress.IPv4Port,
                testCase.PreferredAddress.IPv6Address,
                testCase.PreferredAddress.IPv6Port,
                testCase.PreferredAddress.ConnectionId,
                testCase.PreferredAddress.StatelessResetToken);

            AssertPreferredAddressTupleWrittenFirst(exactEncoded, expectedPreferredAddressValue);
            Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
                exactEncoded,
                QuicTransportParameterRole.Client,
                out QuicTransportParameters parsed));

            Assert.Equal(testCase.InitialSourceConnectionId, parsed.InitialSourceConnectionId);
            Assert.Equal(testCase.ActiveConnectionIdLimit, parsed.ActiveConnectionIdLimit);
            AssertPreferredAddressEqual(testCase.PreferredAddress, parsed.PreferredAddress!);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1154")]
    [Requirement("REQ-QUIC-RFC9000-1156")]
    [Requirement("REQ-QUIC-RFC9000-1157")]
    [Requirement("REQ-QUIC-RFC9000-1158")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_InvalidPreferredAddressAndActiveConnectionIdLimitValuesAreRejected()
    {
        foreach (byte[] invalidEncoded in InvalidTransportParameterBlocks())
        {
            Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
                invalidEncoded,
                QuicTransportParameterRole.Client,
                out _));
        }

        byte[] formatDestination = new byte[256];
        foreach (QuicTransportParameters invalidServerParameters in InvalidServerPreferredAddressParameters())
        {
            Assert.False(QuicTransportParametersCodec.TryFormatTransportParameters(
                invalidServerParameters,
                QuicTransportParameterRole.Server,
                formatDestination,
                out int bytesWritten));
            Assert.Equal(0, bytesWritten);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1162")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ServerOnlyTransportParametersAreRejectedForClientSendAndServerReceive()
    {
        byte[] formatDestination = new byte[256];
        foreach (QuicTransportParameters serverOnlyParameters in ServerOnlyFormatCases())
        {
            Assert.False(QuicTransportParametersCodec.TryFormatTransportParameters(
                serverOnlyParameters,
                QuicTransportParameterRole.Client,
                formatDestination,
                out int bytesWritten));
            Assert.Equal(0, bytesWritten);
        }

        foreach (byte[] clientSentServerOnlyTuple in ServerOnlyParseCases())
        {
            Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
                clientSentServerOnlyTuple,
                QuicTransportParameterRole.Server,
                out _));
        }
    }

    private static IEnumerable<PreferredAddressCase> PreferredAddressCases()
    {
        yield return new PreferredAddressCase(
            InitialSourceConnectionId: [0x10],
            PreferredAddress: CreatePreferredAddress(iteration: 0, connectionIdLength: 1),
            ActiveConnectionIdLimit: 2);
        yield return new PreferredAddressCase(
            InitialSourceConnectionId: [0x10, 0x11],
            PreferredAddress: CreatePreferredAddress(iteration: 1, connectionIdLength: 2, zeroIpv4: true),
            ActiveConnectionIdLimit: 3);
        yield return new PreferredAddressCase(
            InitialSourceConnectionId: [0x10, 0x11, 0x12, 0x13],
            PreferredAddress: CreatePreferredAddress(iteration: 2, connectionIdLength: 4, zeroIpv6: true),
            ActiveConnectionIdLimit: 8);
        yield return new PreferredAddressCase(
            InitialSourceConnectionId: [0x80, 0x81, 0x82, 0x83],
            PreferredAddress: CreatePreferredAddress(iteration: 3, connectionIdLength: 20),
            ActiveConnectionIdLimit: 64);

        Random random = new(0x1157);
        for (int i = 0; i < 16; i++)
        {
            byte[] initialSourceConnectionId = RandomBytes(random, random.Next(1, 9));
            int preferredConnectionIdLength = random.Next(1, 21);
            byte[] preferredConnectionId;
            do
            {
                preferredConnectionId = RandomBytes(random, preferredConnectionIdLength);
            }
            while (preferredConnectionId.AsSpan().SequenceEqual(initialSourceConnectionId));

            yield return new PreferredAddressCase(
                InitialSourceConnectionId: initialSourceConnectionId,
                PreferredAddress: new QuicPreferredAddress
                {
                    IPv4Address = RandomBytes(random, 4),
                    IPv4Port = (ushort)random.Next(1, ushort.MaxValue + 1),
                    IPv6Address = RandomBytes(random, 16),
                    IPv6Port = (ushort)random.Next(1, ushort.MaxValue + 1),
                    ConnectionId = preferredConnectionId,
                    StatelessResetToken = RandomBytes(random, QuicPreferredAddressRequirementTestSupport.StatelessResetTokenLength),
                },
                ActiveConnectionIdLimit: (ulong)random.Next(2, 128));
        }
    }

    private static IEnumerable<byte[]> InvalidTransportParameterBlocks()
    {
        byte[] validPreferredAddressValue = QuicTransportParameterTestData.BuildPreferredAddressValue(
            QuicPreferredAddressRequirementTestSupport.PreferredIpv4Address,
            9443,
            QuicPreferredAddressRequirementTestSupport.PreferredIpv6Address,
            9553,
            QuicPreferredAddressRequirementTestSupport.PreferredConnectionId,
            QuicPreferredAddressRequirementTestSupport.StatelessResetToken);

        yield return QuicTransportParameterTestData.BuildTransportParameterTuple(
            0x0E,
            QuicVarintTestData.EncodeMinimal(0));
        yield return QuicTransportParameterTestData.BuildTransportParameterTuple(
            0x0E,
            QuicVarintTestData.EncodeMinimal(1));
        yield return QuicTransportParameterTestData.BuildTransportParameterTuple(
            0x0D,
            validPreferredAddressValue[..^1]);

        byte[] emptyPreferredConnectionIdValue = QuicTransportParameterTestData.BuildPreferredAddressValue(
            QuicPreferredAddressRequirementTestSupport.PreferredIpv4Address,
            9443,
            QuicPreferredAddressRequirementTestSupport.PreferredIpv6Address,
            9553,
            [],
            QuicPreferredAddressRequirementTestSupport.StatelessResetToken);
        yield return QuicTransportParameterTestData.BuildTransportParameterTuple(
            0x0D,
            emptyPreferredConnectionIdValue);

        byte[] matchingConnectionIdValue = QuicTransportParameterTestData.BuildPreferredAddressValue(
            QuicPreferredAddressRequirementTestSupport.PreferredIpv4Address,
            9443,
            QuicPreferredAddressRequirementTestSupport.PreferredIpv6Address,
            9553,
            QuicPreferredAddressRequirementTestSupport.InitialSourceConnectionId,
            QuicPreferredAddressRequirementTestSupport.StatelessResetToken);
        yield return QuicTransportParameterTestData.BuildTransportParameterBlock(
            QuicTransportParameterTestData.BuildTransportParameterTuple(
                0x0F,
                QuicPreferredAddressRequirementTestSupport.InitialSourceConnectionId),
            QuicTransportParameterTestData.BuildTransportParameterTuple(
                0x0D,
                matchingConnectionIdValue));

        yield return QuicTransportParameterTestData.BuildTransportParameterBlock(
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x0F, []),
            QuicTransportParameterTestData.BuildTransportParameterTuple(
                0x0D,
                validPreferredAddressValue));
    }

    private static IEnumerable<QuicTransportParameters> InvalidServerPreferredAddressParameters()
    {
        yield return new QuicTransportParameters
        {
            InitialSourceConnectionId = [],
            PreferredAddress = QuicPreferredAddressRequirementTestSupport.CreatePreferredAddress(),
        };

        yield return new QuicTransportParameters
        {
            InitialSourceConnectionId = QuicPreferredAddressRequirementTestSupport.InitialSourceConnectionId,
            PreferredAddress = QuicPreferredAddressRequirementTestSupport.CreatePreferredAddress(
                preferredConnectionId: QuicPreferredAddressRequirementTestSupport.InitialSourceConnectionId),
        };

        yield return new QuicTransportParameters
        {
            InitialSourceConnectionId = QuicPreferredAddressRequirementTestSupport.InitialSourceConnectionId,
            PreferredAddress = QuicPreferredAddressRequirementTestSupport.CreatePreferredAddress(
                preferredConnectionId: []),
        };
    }

    private static IEnumerable<QuicTransportParameters> ServerOnlyFormatCases()
    {
        yield return new QuicTransportParameters { OriginalDestinationConnectionId = [0x01, 0x02] };
        yield return new QuicTransportParameters
        {
            StatelessResetToken = RandomBytes(new Random(0x1162), QuicPreferredAddressRequirementTestSupport.StatelessResetTokenLength),
        };
        yield return new QuicTransportParameters
        {
            PreferredAddress = QuicPreferredAddressRequirementTestSupport.CreatePreferredAddress(),
        };
        yield return new QuicTransportParameters { RetrySourceConnectionId = [0xAA, 0xBB] };
    }

    private static IEnumerable<byte[]> ServerOnlyParseCases()
    {
        yield return QuicTransportParameterTestData.BuildTransportParameterTuple(0x00, [0x01, 0x02]);
        yield return QuicTransportParameterTestData.BuildTransportParameterTuple(
            0x02,
            QuicPreferredAddressRequirementTestSupport.StatelessResetToken);
        yield return QuicPreferredAddressRequirementTestSupport.BuildPreferredAddressTuple(
            QuicPreferredAddressRequirementTestSupport.CreatePreferredAddress());
        yield return QuicTransportParameterTestData.BuildTransportParameterTuple(0x10, [0xAA, 0xBB]);
    }

    private static QuicPreferredAddress CreatePreferredAddress(
        int iteration,
        int connectionIdLength,
        bool zeroIpv4 = false,
        bool zeroIpv6 = false)
    {
        byte lowByte = (byte)(0x20 + iteration);
        return new QuicPreferredAddress
        {
            IPv4Address = zeroIpv4 ? [0, 0, 0, 0] : [192, 0, 2, lowByte],
            IPv4Port = zeroIpv4 ? (ushort)0 : (ushort)(9443 + iteration),
            IPv6Address = zeroIpv6
                ? new byte[QuicPreferredAddressRequirementTestSupport.IPv6AddressLength]
                :
                [
                    0x20, 0x01, 0x0D, 0xB8,
                    0x00, 0x01, 0x00, 0x02,
                    0x00, 0x03, 0x00, 0x04,
                    0x00, 0x05, 0x00, lowByte,
                ],
            IPv6Port = zeroIpv6 ? (ushort)0 : (ushort)(9553 + iteration),
            ConnectionId = Enumerable.Range(0, connectionIdLength)
                .Select(value => (byte)(0x30 + iteration + value))
                .ToArray(),
            StatelessResetToken = Enumerable
                .Range(0, QuicPreferredAddressRequirementTestSupport.StatelessResetTokenLength)
                .Select(value => (byte)(0x50 + iteration + value))
                .ToArray(),
        };
    }

    private static byte[] RandomBytes(Random random, int length)
    {
        byte[] buffer = new byte[length];
        random.NextBytes(buffer);
        return buffer;
    }

    private static void AssertPreferredAddressTupleWrittenFirst(byte[] encoded, byte[] expectedPreferredAddressValue)
    {
        Assert.True(encoded.Length >= QuicPreferredAddressRequirementTestSupport.PreferredAddressTupleHeaderLength);
        Assert.Equal(QuicPreferredAddressRequirementTestSupport.PreferredAddressTransportParameterId, encoded[0]);
        Assert.Equal(expectedPreferredAddressValue.Length, encoded[1]);
        Assert.True(expectedPreferredAddressValue.AsSpan().SequenceEqual(
            encoded.AsSpan(
                QuicPreferredAddressRequirementTestSupport.PreferredAddressTupleHeaderLength,
                expectedPreferredAddressValue.Length)));
    }

    private static void AssertPreferredAddressEqual(QuicPreferredAddress expected, QuicPreferredAddress actual)
    {
        Assert.Equal(expected.IPv4Address, actual.IPv4Address);
        Assert.Equal(expected.IPv4Port, actual.IPv4Port);
        Assert.Equal(expected.IPv6Address, actual.IPv6Address);
        Assert.Equal(expected.IPv6Port, actual.IPv6Port);
        Assert.Equal(expected.ConnectionId, actual.ConnectionId);
        Assert.Equal(expected.StatelessResetToken, actual.StatelessResetToken);
    }

    private sealed record PreferredAddressCase(
        byte[] InitialSourceConnectionId,
        QuicPreferredAddress PreferredAddress,
        ulong ActiveConnectionIdLimit);
}
