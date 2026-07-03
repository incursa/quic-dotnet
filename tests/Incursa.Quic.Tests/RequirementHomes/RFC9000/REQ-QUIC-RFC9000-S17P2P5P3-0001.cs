// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P2P5P3-0001")]
public sealed class REQ_QUIC_RFC9000_S17P2P5P3_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientRetryReplayInitialPacketsCarryTheRetrySourceConnectionIdAndToken()
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
            Assert.Equal(QuicS17P2P5P2TestSupport.RetryToken, replayPacket.Token);
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P5P3-0001")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P5P3-0002")]
    [Requirement("RFC9000-S17-2-5-3-P2-S2-R01")]
    public void ClientDoesNotEmitRetryReplayInitialPacketsForARejectedSecondRetry()
    {
        using QuicConnectionRuntime clientRuntime = QuicS17P2P5P2TestSupport.CreateBootstrappedClientRuntime();
        Assert.True(clientRuntime.Transition(
            QuicS17P2P5P2TestSupport.CreateRetryReceivedEvent(1),
            nowTicks: 1).StateChanged);

        QuicConnectionTransitionResult rejectedRetryResult = clientRuntime.Transition(
            QuicS17P2P5P2TestSupport.CreateRetryReceivedEvent(
                2,
                QuicS17P2P5P2TestSupport.MaximumLengthRetrySourceConnectionId,
                QuicS17P2P5P2TestSupport.SingleByteRetryToken),
            nowTicks: 2);

        Assert.False(rejectedRetryResult.StateChanged);
        Assert.Empty(QuicS17P2P3TestSupport.GetInitialSendEffects(rejectedRetryResult.Effects));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P5P3-0001")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P5P3-0002")]
    [Requirement("RFC9000-S17-2-5-3-P2-S2-R01")]
    public void ClientRetryReplayInitialPacketsPreserveBoundaryRetryValuesAndHandshakeBytes()
    {
        using QuicConnectionRuntime clientRuntime = QuicS17P2P5P2TestSupport.CreateBootstrappedClientRuntime();
        byte[] originalClientHelloBytes = QuicResumptionClientHelloTestSupport.GetInitialBootstrapClientHelloBytes(clientRuntime);

        QuicConnectionTransitionResult retryResult = clientRuntime.Transition(
            QuicS17P2P5P2TestSupport.CreateRetryReceivedEvent(
                1,
                QuicS17P2P5P2TestSupport.MaximumLengthRetrySourceConnectionId,
                QuicS17P2P5P2TestSupport.SingleByteRetryToken),
            nowTicks: 1);

        QuicS17P2P5P3TestSupport.RetryReplayInitialPacket[] replayPackets =
            QuicS17P2P5P3TestSupport.ReadRetryReplayInitialPackets(
                retryResult,
                QuicS17P2P5P3TestSupport.CreateServerProtection(
                    QuicS17P2P5P2TestSupport.MaximumLengthRetrySourceConnectionId));

        Assert.NotEmpty(replayPackets);
        ulong expectedOffset = 0;
        foreach (QuicS17P2P5P3TestSupport.RetryReplayInitialPacket replayPacket in replayPackets)
        {
            Assert.Equal(QuicS17P2P5P2TestSupport.MaximumLengthRetrySourceConnectionId, replayPacket.DestinationConnectionId);
            Assert.Equal(QuicS17P2P5P2TestSupport.SingleByteRetryToken, replayPacket.Token);
            Assert.Equal(expectedOffset, replayPacket.CryptoOffset);
            Assert.True(originalClientHelloBytes.AsSpan(
                checked((int)replayPacket.CryptoOffset),
                replayPacket.CryptoPayload.Length).SequenceEqual(replayPacket.CryptoPayload));
            expectedOffset += (ulong)replayPacket.CryptoPayload.Length;
        }

        Assert.Equal((ulong)originalClientHelloBytes.Length, expectedOffset);
    }
}
