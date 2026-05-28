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
}
