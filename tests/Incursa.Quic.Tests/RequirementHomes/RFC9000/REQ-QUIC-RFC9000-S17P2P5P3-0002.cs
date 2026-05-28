// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P2P5P3-0002")]
public sealed class REQ_QUIC_RFC9000_S17P2P5P3_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientRetryReplayInitialPacketsKeepTheRetrySourceConnectionIdAsTheirDestinationConnectionId()
    {
        using QuicConnectionRuntime clientRuntime = QuicS17P2P5P2TestSupport.CreateBootstrappedClientRuntime();

        QuicConnectionTransitionResult retryResult = clientRuntime.Transition(
            QuicS17P2P5P2TestSupport.CreateRetryReceivedEvent(1),
            nowTicks: 1);

        QuicS17P2P5P3TestSupport.RetryReplayInitialPacket[] replayPackets =
            QuicS17P2P5P3TestSupport.ReadRetryReplayInitialPackets(
                retryResult,
                QuicS17P2P5P3TestSupport.CreateServerProtection());

        Assert.NotEmpty(replayPackets);
        foreach (QuicS17P2P5P3TestSupport.RetryReplayInitialPacket replayPacket in replayPackets)
        {
            Assert.Equal(QuicS17P2P5P2TestSupport.RetrySourceConnectionId, replayPacket.DestinationConnectionId);
        }
    }
}
