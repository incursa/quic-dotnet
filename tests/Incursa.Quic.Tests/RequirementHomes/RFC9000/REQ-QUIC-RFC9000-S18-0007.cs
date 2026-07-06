// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S18-0007")]
public sealed class REQ_QUIC_RFC9000_S18_0007
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatTransportParameters_EncodesTransportParametersAsHandshakeBytes()
    {
        QuicTransportParameters parameters = new()
        {
            MaxIdleTimeout = 25,
            DisableActiveMigration = true,
            InitialSourceConnectionId = [0x11, 0x22],
        };

        byte[] expected = QuicTransportParameterTestData.BuildTransportParameterBlock(
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x01, QuicVarintTestData.EncodeMinimal(25)),
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x0C, []),
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x0F, [0x11, 0x22]));

        Span<byte> destination = stackalloc byte[64];
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
        Assert.Equal(new byte[] { 0x11, 0x22 }, parsed.InitialSourceConnectionId);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseTransportParameters_RejectsTruncatedHandshakeBytes()
    {
        byte[] encoded = QuicTransportParameterTestData.BuildTransportParameterTuple(
            0x01,
            QuicVarintTestData.EncodeMinimal(25));

        Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
            encoded[..^1],
            QuicTransportParameterRole.Client,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryFormatTransportParameters_ProducesTheEmptyHandshakeByteSequence()
    {
        Span<byte> destination = stackalloc byte[1];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            new QuicTransportParameters(),
            QuicTransportParameterRole.Client,
            destination,
            out int bytesWritten));

        Assert.Equal(0, bytesWritten);

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            ReadOnlySpan<byte>.Empty,
            QuicTransportParameterRole.Client,
            out QuicTransportParameters parsed));

        Assert.Null(parsed.MaxIdleTimeout);
        Assert.False(parsed.DisableActiveMigration);
        Assert.Null(parsed.InitialSourceConnectionId);
        Assert.Null(parsed.PreferredAddress);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void TryFormatTransportParameters_FuzzRoundTripsClientHandshakeByteSequences()
    {
        QuicTransportParameters[] scenarios =
        [
            new()
            {
                MaxIdleTimeout = 0,
                InitialMaxData = 0,
                InitialSourceConnectionId = [0x01],
            },
            new()
            {
                MaxIdleTimeout = 25,
                MaxUdpPayloadSize = 1_200,
                InitialMaxStreamDataBidiLocal = 1_024,
                InitialMaxStreamDataBidiRemote = 2_048,
                InitialMaxStreamDataUni = 4_096,
                InitialMaxStreamsBidi = 4,
                InitialMaxStreamsUni = 8,
                MaxAckDelay = 25,
                ActiveConnectionIdLimit = 2,
                InitialSourceConnectionId = [0x10, 0x20],
            },
            new()
            {
                MaxIdleTimeout = 60_000,
                MaxUdpPayloadSize = 1_452,
                InitialMaxData = 1 << 20,
                MaxDatagramFrameSize = 1_200,
                DisableActiveMigration = true,
                GreaseQuicBit = true,
                InitialSourceConnectionId = [0xAA, 0xBB, 0xCC],
            },
        ];

        foreach (QuicTransportParameters parameters in scenarios)
        {
            byte[] destination = new byte[256];

            Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
                parameters,
                QuicTransportParameterRole.Client,
                destination,
                out int bytesWritten));
            Assert.True(bytesWritten >= 0);

            Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
                destination.AsSpan(0, bytesWritten),
                QuicTransportParameterRole.Server,
                out QuicTransportParameters parsed));

            AssertEquivalentClientParameters(parameters, parsed);
        }
    }

    private static void AssertEquivalentClientParameters(QuicTransportParameters expected, QuicTransportParameters actual)
    {
        Assert.Equal(expected.MaxIdleTimeout, actual.MaxIdleTimeout);
        Assert.Equal(expected.MaxUdpPayloadSize, actual.MaxUdpPayloadSize);
        Assert.Equal(expected.MaxDatagramFrameSize, actual.MaxDatagramFrameSize);
        Assert.Equal(expected.InitialMaxData, actual.InitialMaxData);
        Assert.Equal(expected.InitialMaxStreamDataBidiLocal, actual.InitialMaxStreamDataBidiLocal);
        Assert.Equal(expected.InitialMaxStreamDataBidiRemote, actual.InitialMaxStreamDataBidiRemote);
        Assert.Equal(expected.InitialMaxStreamDataUni, actual.InitialMaxStreamDataUni);
        Assert.Equal(expected.InitialMaxStreamsBidi, actual.InitialMaxStreamsBidi);
        Assert.Equal(expected.InitialMaxStreamsUni, actual.InitialMaxStreamsUni);
        Assert.Equal(expected.MaxAckDelay, actual.MaxAckDelay);
        Assert.Equal(expected.ActiveConnectionIdLimit, actual.ActiveConnectionIdLimit);
        Assert.Equal(expected.DisableActiveMigration, actual.DisableActiveMigration);
        Assert.Equal(expected.GreaseQuicBit, actual.GreaseQuicBit);
        Assert.Equal(expected.InitialSourceConnectionId, actual.InitialSourceConnectionId);
    }
}
