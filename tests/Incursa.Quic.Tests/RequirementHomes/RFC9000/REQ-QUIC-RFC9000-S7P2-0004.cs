// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S7P2-0004")]
public sealed class REQ_QUIC_RFC9000_S7P2_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [Requirement("RFC9000-S5-1-P4-S1-R01")]
    public async Task ClientHostGeneratesAnIndependentFirstInitialDestinationConnectionId()
    {
        var remoteEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        QuicClientConnectionSettings settings = QuicClientConnectionOptionsValidator.Capture(
            QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(remoteEndPoint),
            "options");

        await using QuicClientConnectionHost host = new(settings);

        byte[] initialDestinationConnectionId = host.InitialDestinationConnectionId;
        byte[] routeConnectionId = host.RouteConnectionId;

        Assert.Equal(8, initialDestinationConnectionId.Length);
        Assert.False(QuicS7P2FirstFlightConnectionIdTestSupport.IsAllZero(initialDestinationConnectionId));
        Assert.False(initialDestinationConnectionId.AsSpan().SequenceEqual(routeConnectionId));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [Requirement("RFC9000-S5-1-P4-S1-R01")]
    public async Task ClientHostDoesNotReuseFirstInitialDestinationConnectionIdsAcrossConnections()
    {
        var remoteEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        QuicClientConnectionSettings firstSettings = QuicClientConnectionOptionsValidator.Capture(
            QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(remoteEndPoint),
            "options");
        QuicClientConnectionSettings secondSettings = QuicClientConnectionOptionsValidator.Capture(
            QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(remoteEndPoint),
            "options");

        await using QuicClientConnectionHost firstHost = new(firstSettings);
        await using QuicClientConnectionHost secondHost = new(secondSettings);

        byte[] firstInitialDestinationConnectionId = firstHost.InitialDestinationConnectionId;
        byte[] secondInitialDestinationConnectionId = secondHost.InitialDestinationConnectionId;

        Assert.Equal(8, firstInitialDestinationConnectionId.Length);
        Assert.Equal(8, secondInitialDestinationConnectionId.Length);
        Assert.False(firstInitialDestinationConnectionId.AsSpan().SequenceEqual(secondInitialDestinationConnectionId));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    [Requirement("RFC9000-S5-1-P4-S1-R01")]
    public async Task ClientHostKeepsTheUnpredictableInitialDestinationSeparateFromTheChosenSourceConnectionId()
    {
        var remoteEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        QuicClientConnectionSettings settings = QuicClientConnectionOptionsValidator.Capture(
            QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(remoteEndPoint),
            "options");

        await using QuicClientConnectionHost host = new(settings);

        byte[] initialDestinationConnectionId = host.InitialDestinationConnectionId;
        byte[] routeConnectionId = host.RouteConnectionId;

        Assert.Equal(8, initialDestinationConnectionId.Length);
        Assert.Equal(8, routeConnectionId.Length);
        Assert.False(QuicS7P2FirstFlightConnectionIdTestSupport.IsAllZero(initialDestinationConnectionId));
        Assert.False(QuicS7P2FirstFlightConnectionIdTestSupport.IsAllZero(routeConnectionId));
        Assert.False(initialDestinationConnectionId.AsSpan().SequenceEqual(routeConnectionId));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    [Requirement("RFC9000-S5-1-P4-S1-R01")]
    public async Task ClientHostFuzzGeneratesDistinctNonZeroFirstInitialDestinationConnectionIds()
    {
        HashSet<string> generatedInitialDestinationConnectionIds = [];

        for (int index = 0; index < 4; index++)
        {
            var remoteEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
            QuicClientConnectionSettings settings = QuicClientConnectionOptionsValidator.Capture(
                QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(remoteEndPoint),
                "options");

            await using QuicClientConnectionHost host = new(settings);

            byte[] initialDestinationConnectionId = host.InitialDestinationConnectionId;
            byte[] routeConnectionId = host.RouteConnectionId;

            Assert.Equal(8, initialDestinationConnectionId.Length);
            Assert.False(QuicS7P2FirstFlightConnectionIdTestSupport.IsAllZero(initialDestinationConnectionId));
            Assert.False(initialDestinationConnectionId.AsSpan().SequenceEqual(routeConnectionId));
            Assert.True(generatedInitialDestinationConnectionIds.Add(Convert.ToHexString(initialDestinationConnectionId)));
        }
    }
}
