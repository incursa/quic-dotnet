// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S7-2-P3-S2-R01")]
public sealed class REQ_QUIC_RFC9000_0309
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ClientHostUsesAnInitialDestinationConnectionIdAtLeastEightBytesLong()
    {
        var remoteEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        QuicClientConnectionSettings settings = QuicClientConnectionOptionsValidator.Capture(
            QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(remoteEndPoint),
            "options");

        await using QuicClientConnectionHost host = new(settings);

        byte[] initialDestinationConnectionId = host.InitialDestinationConnectionId;

        Assert.True(initialDestinationConnectionId.Length >= 8);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task ClientHostDoesNotUseAZeroLengthFirstInitialDestinationConnectionId()
    {
        var remoteEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        QuicClientConnectionSettings settings = QuicClientConnectionOptionsValidator.Capture(
            QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(remoteEndPoint),
            "options");

        await using QuicClientConnectionHost host = new(settings);

        byte[] initialDestinationConnectionId = host.InitialDestinationConnectionId;

        Assert.NotEmpty(initialDestinationConnectionId);
        Assert.False(initialDestinationConnectionId.Length < 8);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public async Task ClientHostUsesTheEightByteMinimumForTheFirstInitialDestinationConnectionId()
    {
        var remoteEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        QuicClientConnectionSettings settings = QuicClientConnectionOptionsValidator.Capture(
            QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(remoteEndPoint),
            "options");

        await using QuicClientConnectionHost host = new(settings);

        byte[] initialDestinationConnectionId = host.InitialDestinationConnectionId;

        Assert.Equal(8, initialDestinationConnectionId.Length);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public async Task Fuzz_ClientHostInitialDestinationConnectionIdNeverFallsBelowEightBytes()
    {
        for (int iteration = 0; iteration < 6; iteration++)
        {
            var remoteEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
            QuicClientConnectionSettings settings = QuicClientConnectionOptionsValidator.Capture(
                QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(remoteEndPoint),
                $"options{iteration}");

            await using QuicClientConnectionHost host = new(settings);

            byte[] initialDestinationConnectionId = host.InitialDestinationConnectionId;

            Assert.True(initialDestinationConnectionId.Length >= 8);
            Assert.Equal(8, initialDestinationConnectionId.Length);
            Assert.False(QuicS7P2FirstFlightConnectionIdTestSupport.IsAllZero(initialDestinationConnectionId));
        }
    }
}
