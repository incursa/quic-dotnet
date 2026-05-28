// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers.Binary;

namespace Incursa.Quic.Tests;

public sealed class QuicTransportParametersCodecUnitTests
{
    [Fact]
    public void TryFormatTransportParameters_RoundTripsPreferredAddressAndDisableActiveMigration()
    {
        QuicPreferredAddress preferredAddress = CreatePreferredAddress();
        byte[] preferredAddressValue = CreatePreferredAddressValue();

        QuicTransportParameters parameters = new()
        {
            MaxIdleTimeout = 25,
            DisableActiveMigration = true,
            PreferredAddress = preferredAddress,
            ActiveConnectionIdLimit = 8,
            InitialSourceConnectionId = [0x11, 0x22],
        };

        byte[] expected = QuicTransportParameterTestData.BuildTransportParameterBlock(
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x01, QuicVarintTestData.EncodeMinimal(25)),
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x0C, []),
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x0D, preferredAddressValue),
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x0E, QuicVarintTestData.EncodeMinimal(8)),
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x0F, [0x11, 0x22]));

        Span<byte> destination = stackalloc byte[256];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            QuicTransportParameterRole.Server,
            destination,
            out int bytesWritten));

        Assert.Equal(expected.Length, bytesWritten);
        Assert.True(expected.AsSpan().SequenceEqual(destination[..bytesWritten]));

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            destination[..bytesWritten],
            QuicTransportParameterRole.Client,
            out QuicTransportParameters parsed));

        Assert.Equal(25UL, parsed.MaxIdleTimeout);
        Assert.True(parsed.DisableActiveMigration);
        Assert.NotNull(parsed.PreferredAddress);
        Assert.Equal(8UL, parsed.ActiveConnectionIdLimit);
        Assert.True(parameters.InitialSourceConnectionId!.AsSpan().SequenceEqual(parsed.InitialSourceConnectionId!));
        AssertPreferredAddressEqual(preferredAddress, parsed.PreferredAddress!);
    }

    [Theory]
    [MemberData(nameof(ClientFormatRejectionCases))]
    public void TryFormatTransportParameters_RejectsServerOnlyParametersFromClients(object parametersObject)
    {
        QuicTransportParameters parameters = Assert.IsType<QuicTransportParameters>(parametersObject);

        Span<byte> destination = stackalloc byte[64];

        Assert.False(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            QuicTransportParameterRole.Client,
            destination,
            out int bytesWritten));

        Assert.Equal(0, bytesWritten);
    }

    public static IEnumerable<object[]> ClientFormatRejectionCases()
    {
        yield return new object[]
        {
            new QuicTransportParameters
            {
                OriginalDestinationConnectionId = [0x10, 0x11],
            },
        };

        yield return new object[]
        {
            new QuicTransportParameters
            {
                StatelessResetToken = CreateStatelessResetToken(),
            },
        };

        yield return new object[]
        {
            new QuicTransportParameters
            {
                PreferredAddress = CreatePreferredAddress(),
            },
        };

        yield return new object[]
        {
            new QuicTransportParameters
            {
                RetrySourceConnectionId = [0x33, 0x44, 0x55],
            },
        };
    }

    [Theory]
    [MemberData(nameof(ServerParseRejectionCases))]
    public void TryParseTransportParameters_RejectsServerOnlyParametersWhenParsingAsServer(byte[] encoded)
    {
        Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
            encoded,
            QuicTransportParameterRole.Server,
            out _));
    }

    public static IEnumerable<object[]> ServerParseRejectionCases()
    {
        yield return new object[]
        {
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x00, [0x01, 0x02]),
        };

        yield return new object[]
        {
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x02, CreateStatelessResetToken()),
        };

        yield return new object[]
        {
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x0D, CreatePreferredAddressValue()),
        };

        yield return new object[]
        {
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x10, [0x33, 0x44]),
        };
    }

    [Theory]
    [MemberData(nameof(DuplicateParameterCases))]
    public void TryParseTransportParameters_RejectsDuplicateParameters(byte[] encoded)
    {
        Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
            encoded,
            QuicTransportParameterRole.Client,
            out _));
    }

    public static IEnumerable<object[]> DuplicateParameterCases()
    {
        yield return new object[]
        {
            QuicTransportParameterTestData.BuildTransportParameterBlock(
                QuicTransportParameterTestData.BuildTransportParameterTuple(0x01, QuicVarintTestData.EncodeMinimal(25)),
                QuicTransportParameterTestData.BuildTransportParameterTuple(0x01, QuicVarintTestData.EncodeMinimal(33))),
        };

        yield return new object[]
        {
            QuicTransportParameterTestData.BuildTransportParameterBlock(
                QuicTransportParameterTestData.BuildTransportParameterTuple(27, [0xAA]),
                QuicTransportParameterTestData.BuildTransportParameterTuple(27, [0xBB])),
        };
    }

    [Theory]
    [MemberData(nameof(TruncatedEncodingCases))]
    public void TryParseTransportParameters_RejectsTruncatedEncodings(byte[] encoded)
    {
        Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
            encoded,
            QuicTransportParameterRole.Client,
            out _));
    }

    [Fact]
    public void TryFormatTransportParameters_EmitsGreaseQuicBitAsEmptyParameter()
    {
        QuicTransportParameters parameters = new()
        {
            GreaseQuicBit = true,
        };

        byte[] expected = QuicTransportParameterTestData.BuildTransportParameterTuple(0x2AB2, []);

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            QuicTransportParameterRole.Client,
            destination,
            out int bytesWritten));

        Assert.Equal(expected.Length, bytesWritten);
        Assert.True(expected.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    public void TryFormatTransportParameters_EmitsVersionInformationForClientAndServerSnapshots()
    {
        QuicTransportParameters clientParameters = CreateVersionInformationTransportParameters(
            QuicVersionNegotiation.Version2,
            [QuicVersionNegotiation.Version2, QuicVersionNegotiation.Version1, QuicVersionNegotiation.CreateReservedVersion(0x10203040)]);

        QuicTransportParameters serverParameters = CreateVersionInformationTransportParameters(
            QuicVersionNegotiation.Version1,
            [QuicVersionNegotiation.Version1, QuicVersionNegotiation.Version2]);

        AssertVersionInformationFormatsAsExpected(clientParameters, QuicTransportParameterRole.Client);
        AssertVersionInformationFormatsAsExpected(serverParameters, QuicTransportParameterRole.Server);
    }

    [Fact]
    public void TryParseTransportParameters_AcceptsAValidVersionInformationPayload()
    {
        QuicTransportParameters parameters = CreateVersionInformationTransportParameters(
            QuicVersionNegotiation.Version2,
            [QuicVersionNegotiation.Version2, QuicVersionNegotiation.Version1]);

        Span<byte> destination = stackalloc byte[128];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            QuicTransportParameterRole.Client,
            destination,
            out int bytesWritten));

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            destination[..bytesWritten],
            QuicTransportParameterRole.Server,
            out QuicTransportParameters parsed));

        Assert.NotNull(parsed.VersionInformation);
        AssertVersionInformationEqual(parameters.VersionInformation!, parsed.VersionInformation!);
    }

    [Fact]
    public void TryParseTransportParameters_RejectsMalformedVersionInformationPayloads()
    {
        Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x11, [0x00, 0x00, 0x00, 0x00]),
            QuicTransportParameterRole.Server,
            out _));

        Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x11, [0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]),
            QuicTransportParameterRole.Server,
            out _));

        Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x11, [0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]),
            QuicTransportParameterRole.Server,
            out _));
    }

    [Fact]
    public void TryParseTransportParameters_RejectsNonEmptyGreaseQuicBitParameter()
    {
        byte[] encoded = QuicTransportParameterTestData.BuildTransportParameterTuple(0x2AB2, [0x01]);

        Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
            encoded,
            QuicTransportParameterRole.Client,
            out _));
    }

    public static IEnumerable<object[]> TruncatedEncodingCases()
    {
        yield return new object[]
        {
            QuicVarintTestData.EncodeWithLength(0x01, 2)[..1],
        };

        yield return new object[]
        {
            new byte[] { 0x01, 0x40 },
        };

        yield return new object[]
        {
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x0D, CreatePreferredAddressValue())[..^1],
        };
    }

    private static QuicPreferredAddress CreatePreferredAddress()
    {
        return new QuicPreferredAddress
        {
            IPv4Address = [192, 0, 2, 1],
            IPv4Port = 443,
            IPv6Address = [0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06],
            IPv6Port = 8443,
            ConnectionId = [0x10, 0x11],
            StatelessResetToken = CreateStatelessResetToken(),
        };
    }

    private static byte[] CreatePreferredAddressValue()
    {
        QuicPreferredAddress preferredAddress = CreatePreferredAddress();

        return QuicTransportParameterTestData.BuildPreferredAddressValue(
            preferredAddress.IPv4Address,
            preferredAddress.IPv4Port,
            preferredAddress.IPv6Address,
            preferredAddress.IPv6Port,
            preferredAddress.ConnectionId,
            preferredAddress.StatelessResetToken);
    }

    private static byte[] CreateStatelessResetToken()
    {
        return [0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F];
    }

    private static void AssertPreferredAddressEqual(QuicPreferredAddress expected, QuicPreferredAddress actual)
    {
        Assert.True(expected.IPv4Address.AsSpan().SequenceEqual(actual.IPv4Address));
        Assert.Equal(expected.IPv4Port, actual.IPv4Port);
        Assert.True(expected.IPv6Address.AsSpan().SequenceEqual(actual.IPv6Address));
        Assert.Equal(expected.IPv6Port, actual.IPv6Port);
        Assert.True(expected.ConnectionId.AsSpan().SequenceEqual(actual.ConnectionId));
        Assert.True(expected.StatelessResetToken.AsSpan().SequenceEqual(actual.StatelessResetToken));
    }

    private static QuicTransportParameters CreateVersionInformationTransportParameters(
        uint chosenVersion,
        uint[] availableVersions)
    {
        return new QuicTransportParameters
        {
            VersionInformation = new QuicVersionInformation
            {
                ChosenVersion = chosenVersion,
                AvailableVersions = availableVersions,
            },
        };
    }

    private static void AssertVersionInformationFormatsAsExpected(
        QuicTransportParameters parameters,
        QuicTransportParameterRole senderRole)
    {
        byte[] expected = QuicTransportParameterTestData.BuildTransportParameterTuple(
            0x11,
            BuildVersionInformationValue(
                parameters.VersionInformation!.ChosenVersion,
                parameters.VersionInformation.AvailableVersions));

        Span<byte> destination = stackalloc byte[128];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            senderRole,
            destination,
            out int bytesWritten));

        Assert.Equal(expected.Length, bytesWritten);
        Assert.True(expected.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    private static byte[] BuildVersionInformationValue(uint chosenVersion, ReadOnlySpan<uint> availableVersions)
    {
        byte[] value = new byte[sizeof(uint) + (availableVersions.Length * sizeof(uint))];
        BinaryPrimitives.WriteUInt32BigEndian(value, chosenVersion);

        int offset = sizeof(uint);
        for (int index = 0; index < availableVersions.Length; index++)
        {
            BinaryPrimitives.WriteUInt32BigEndian(
                value.AsSpan(offset, sizeof(uint)),
                availableVersions[index]);
            offset += sizeof(uint);
        }

        return value;
    }

    private static void AssertVersionInformationEqual(QuicVersionInformation expected, QuicVersionInformation actual)
    {
        Assert.Equal(expected.ChosenVersion, actual.ChosenVersion);
        Assert.True(expected.AvailableVersions.AsSpan().SequenceEqual(actual.AvailableVersions));
    }
}
