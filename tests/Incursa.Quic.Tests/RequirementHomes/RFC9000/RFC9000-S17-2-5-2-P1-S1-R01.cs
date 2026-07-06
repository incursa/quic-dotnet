// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S17-2-5-2-P1-S1-R01">After the client has received and processed an Initial or Retry packet from the server, it MUST discard any subsequent Retry packets that it receives.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S17-2-5-2-P1-S1-R01")]
public sealed class REQ_QUIC_RFC9000_1037
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="RFC9000-S17-2-5-2-P1-S1-R01">After the client has received and processed an Initial or Retry packet from the server, it MUST discard any subsequent Retry packets that it receives.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("RFC9000-S17-2-5-2-P1-S1-R01")]
    public void ClientDiscardsSubsequentRetryPacketsAfterProcessingTheFirstRetryPacket()
    {
        QuicConnectionRuntime runtime = QuicS17P2P5P2TestSupport.CreateBootstrappedClientRuntime();
        QuicConnectionRetryReceivedEvent retryReceivedEvent = QuicS17P2P5P2TestSupport.CreateRetryReceivedEvent(1);
        Assert.True(runtime.Transition(retryReceivedEvent, nowTicks: 1).StateChanged);

        QuicConnectionRetryReceivedEvent duplicateRetryReceivedEvent = QuicS17P2P5P2TestSupport.CreateRetryReceivedEvent(2);
        QuicConnectionTransitionResult duplicateRetryResult = runtime.Transition(duplicateRetryReceivedEvent, nowTicks: 2);

        Assert.False(duplicateRetryResult.StateChanged);
        Assert.Empty(duplicateRetryResult.Effects);
        Assert.Equal(QuicConnectionPhase.Establishing, runtime.Phase);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [Requirement("RFC9000-S17-2-5-2-P1-S1-R01")]
    public void ClientKeepsTheFirstRetryOutcomeWhenASecondRetryArrives()
    {
        QuicConnectionRuntime runtime = QuicS17P2P5P2TestSupport.CreateBootstrappedClientRuntime();
        QuicConnectionTransitionResult firstRetryResult = runtime.Transition(
            QuicS17P2P5P2TestSupport.CreateRetryReceivedEvent(1),
            nowTicks: 1);

        QuicConnectionTransitionResult secondRetryResult = runtime.Transition(
            QuicS17P2P5P2TestSupport.CreateRetryReceivedEvent(
                2,
                QuicS17P2P5P2TestSupport.MaximumLengthRetrySourceConnectionId,
                QuicS17P2P5P2TestSupport.SingleByteRetryToken),
            nowTicks: 2);

        QuicS17P2P5P3TestSupport.RetryReplayInitialPacket firstReplayPacket =
            QuicS17P2P5P2TestSupport.ReadSingleRetryReplayInitialPacket(firstRetryResult);
        Assert.Equal(QuicS17P2P5P2TestSupport.RetrySourceConnectionId, firstReplayPacket.DestinationConnectionId);
        Assert.Equal(QuicS17P2P5P2TestSupport.RetryToken, firstReplayPacket.Token);
        Assert.False(secondRetryResult.StateChanged);
        Assert.Empty(secondRetryResult.Effects);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    [Requirement("RFC9000-S17-2-5-2-P1-S1-R01")]
    public void ClientDiscardsSubsequentRetryPacketsWithDifferentRetryValues()
    {
        QuicConnectionRuntime runtime = QuicS17P2P5P2TestSupport.CreateBootstrappedClientRuntime();
        Assert.True(runtime.Transition(
            QuicS17P2P5P2TestSupport.CreateRetryReceivedEvent(1),
            nowTicks: 1).StateChanged);

        QuicConnectionTransitionResult changedRetryResult = runtime.Transition(
            QuicS17P2P5P2TestSupport.CreateRetryReceivedEvent(
                2,
                QuicS17P2P5P2TestSupport.MaximumLengthRetrySourceConnectionId,
                QuicS17P2P5P2TestSupport.SingleByteRetryToken),
            nowTicks: 2);

        Assert.False(changedRetryResult.StateChanged);
        Assert.Empty(changedRetryResult.Effects);
        Assert.Equal(QuicConnectionPhase.Establishing, runtime.Phase);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    [Requirement("RFC9000-S17-2-5-2-P1-S1-R01")]
    public void ClientDiscardsAllSubsequentRetryPacketsAcrossVariedRetryValues()
    {
        (byte[] FirstRetrySourceConnectionId, byte[] FirstRetryToken, byte[] SecondRetrySourceConnectionId, byte[] SecondRetryToken, byte[] ThirdRetrySourceConnectionId, byte[] ThirdRetryToken)[] retryCases =
        [
            ([0x21], [0x31], [0x41], [0x51], [0x61], [0x71]),
            ([0x22, 0x23, 0x24, 0x25], [0x32, 0x33, 0x34, 0x35, 0x36], [0x42, 0x43, 0x44], [0x52, 0x53], [0x62, 0x63], [0x72, 0x73, 0x74]),
            (
                QuicS17P2P5P2TestSupport.MaximumLengthRetrySourceConnectionId,
                [0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F],
                [0x61, 0x62, 0x63, 0x64],
                [0x71, 0x72, 0x73],
                [0x81, 0x82, 0x83, 0x84, 0x85],
                [0x91, 0x92]),
        ];

        foreach ((byte[] firstRetrySourceConnectionId, byte[] firstRetryToken, byte[] secondRetrySourceConnectionId, byte[] secondRetryToken, byte[] thirdRetrySourceConnectionId, byte[] thirdRetryToken) in retryCases)
        {
            QuicConnectionRuntime runtime = QuicS17P2P5P2TestSupport.CreateBootstrappedClientRuntime();

            QuicConnectionTransitionResult firstRetryResult = runtime.Transition(
                QuicS17P2P5P2TestSupport.CreateRetryReceivedEvent(
                    1,
                    firstRetrySourceConnectionId,
                    firstRetryToken),
                nowTicks: 1);

            QuicS17P2P5P3TestSupport.RetryReplayInitialPacket replayPacket =
                QuicS17P2P5P2TestSupport.ReadSingleRetryReplayInitialPacket(
                    firstRetryResult,
                    firstRetrySourceConnectionId);

            QuicConnectionTransitionResult secondRetryResult = runtime.Transition(
                QuicS17P2P5P2TestSupport.CreateRetryReceivedEvent(
                    2,
                    secondRetrySourceConnectionId,
                    secondRetryToken),
                nowTicks: 2);
            QuicConnectionTransitionResult thirdRetryResult = runtime.Transition(
                QuicS17P2P5P2TestSupport.CreateRetryReceivedEvent(
                    3,
                    thirdRetrySourceConnectionId,
                    thirdRetryToken),
                nowTicks: 3);

            Assert.True(firstRetryResult.StateChanged);
            Assert.Equal(firstRetrySourceConnectionId, replayPacket.DestinationConnectionId);
            Assert.Equal(firstRetryToken, replayPacket.Token);
            Assert.False(secondRetryResult.StateChanged);
            Assert.Empty(secondRetryResult.Effects);
            Assert.False(thirdRetryResult.StateChanged);
            Assert.Empty(thirdRetryResult.Effects);
            Assert.Equal(QuicConnectionPhase.Establishing, runtime.Phase);
        }
    }
}
