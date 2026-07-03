// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S17-2-5-3-P2-S2-R01")]
public sealed class REQ_QUIC_RFC9000_1050
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientRetryReplayInitialPacketsPreserveTheOriginalHandshakeMessageBytes()
    {
        using QuicConnectionRuntime clientRuntime = QuicS17P2P5P2TestSupport.CreateBootstrappedClientRuntime();
        byte[] originalClientHelloBytes = QuicResumptionClientHelloTestSupport.GetInitialBootstrapClientHelloBytes(clientRuntime);

        QuicConnectionTransitionResult retryResult = clientRuntime.Transition(
            QuicS17P2P5P2TestSupport.CreateRetryReceivedEvent(1),
            nowTicks: 1);

        QuicS17P2P5P3TestSupport.RetryReplayInitialPacket[] replayPackets =
            QuicS17P2P5P3TestSupport.ReadRetryReplayInitialPackets(
                retryResult,
                QuicS17P2P5P3TestSupport.CreateServerProtection());

        Assert.NotEmpty(replayPackets);

        ulong expectedOffset = 0;
        foreach (QuicS17P2P5P3TestSupport.RetryReplayInitialPacket replayPacket in replayPackets)
        {
            Assert.Equal(expectedOffset, replayPacket.CryptoOffset);
            Assert.True(originalClientHelloBytes.AsSpan(
                checked((int)replayPacket.CryptoOffset),
                replayPacket.CryptoPayload.Length).SequenceEqual(replayPacket.CryptoPayload));
            expectedOffset += (ulong)replayPacket.CryptoPayload.Length;
        }

        Assert.Equal((ulong)originalClientHelloBytes.Length, expectedOffset);
    }
}
