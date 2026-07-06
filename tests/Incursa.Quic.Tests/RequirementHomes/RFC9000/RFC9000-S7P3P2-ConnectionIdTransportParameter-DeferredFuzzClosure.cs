// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class RFC9000_S7P3P2_ConnectionIdTransportParameter_DeferredFuzzClosure
{
    [Theory]
    [InlineData(0, 1, 2, 0x10)]
    [InlineData(1, 8, 12, 0x20)]
    [InlineData(8, 16, 20, 0x30)]
    [InlineData(20, 20, 20, 0x40)]
    [Requirement("RFC9000-S7-3-P2-S1-R01")]
    [Requirement("RFC9000-S7-3-P2-S2-R01")]
    [Requirement("RFC9000-S7-3-P2-S3-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ServerTransportParameterConnectionIdFuzz_RoundTripsObservedBindingFields(
        int initialSourceLength,
        int originalDestinationLength,
        int retrySourceLength,
        int seed)
    {
        byte[] initialSourceConnectionId = CreateConnectionId(initialSourceLength, seed);
        byte[] originalDestinationConnectionId = CreateConnectionId(originalDestinationLength, seed + 0x20);
        byte[] retrySourceConnectionId = CreateConnectionId(retrySourceLength, seed + 0x40);
        QuicTransportParameters parameters = new()
        {
            InitialSourceConnectionId = initialSourceConnectionId,
            OriginalDestinationConnectionId = originalDestinationConnectionId,
            RetrySourceConnectionId = retrySourceConnectionId,
        };

        QuicTransportParameters parsed = QuicS7P3ConnectionIdBindingTestSupport.FormatAndParse(
            parameters,
            QuicTransportParameterRole.Server,
            QuicTransportParameterRole.Client);

        Assert.Equal(initialSourceConnectionId, parsed.InitialSourceConnectionId);
        Assert.Equal(originalDestinationConnectionId, parsed.OriginalDestinationConnectionId);
        Assert.Equal(retrySourceConnectionId, parsed.RetrySourceConnectionId);
        Assert.True(QuicTransportParametersCodec.TryValidateConnectionIdBindings(
            QuicTransportParameterRole.Client,
            originalDestinationConnectionId,
            initialSourceConnectionId,
            usedRetry: true,
            retrySourceConnectionId,
            parsed,
            out QuicConnectionIdBindingValidationError validationError));
        Assert.Equal(QuicConnectionIdBindingValidationError.None, validationError);
    }

    [Theory]
    [InlineData(0, 0x60)]
    [InlineData(1, 0x70)]
    [InlineData(8, 0x80)]
    [InlineData(20, 0x90)]
    [Requirement("RFC9000-S7-3-P2-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ClientTransportParameterConnectionIdFuzz_EmitsOnlyInitialSourceConnectionId(
        int initialSourceLength,
        int seed)
    {
        byte[] initialSourceConnectionId = CreateConnectionId(initialSourceLength, seed);
        QuicTransportParameters parameters = new()
        {
            InitialSourceConnectionId = initialSourceConnectionId,
        };

        QuicTransportParameters parsed = QuicS7P3ConnectionIdBindingTestSupport.FormatAndParse(
            parameters,
            QuicTransportParameterRole.Client,
            QuicTransportParameterRole.Server);

        Assert.Equal(initialSourceConnectionId, parsed.InitialSourceConnectionId);
        Assert.Null(parsed.OriginalDestinationConnectionId);
        Assert.Null(parsed.RetrySourceConnectionId);
    }

    [Theory]
    [InlineData(1, 0xA0)]
    [InlineData(8, 0xB0)]
    [InlineData(20, 0xC0)]
    [Requirement("RFC9000-S7-3-P2-S2-R01")]
    [Requirement("RFC9000-S7-3-P2-S3-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ClientTransportParameterConnectionIdFuzz_RejectsServerOnlyBindingFields(
        int connectionIdLength,
        int seed)
    {
        QuicTransportParameters parameters = new()
        {
            InitialSourceConnectionId = CreateConnectionId(connectionIdLength, seed),
            OriginalDestinationConnectionId = CreateConnectionId(connectionIdLength, seed + 0x20),
            RetrySourceConnectionId = CreateConnectionId(connectionIdLength, seed + 0x40),
        };

        Span<byte> destination = stackalloc byte[256];
        Assert.False(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            QuicTransportParameterRole.Client,
            destination,
            out int bytesWritten));
        Assert.Equal(0, bytesWritten);
    }

    private static byte[] CreateConnectionId(int length, int seed)
    {
        byte[] connectionId = new byte[length];
        for (int index = 0; index < connectionId.Length; index++)
        {
            connectionId[index] = unchecked((byte)(seed + (index * 13)));
        }

        return connectionId;
    }
}
