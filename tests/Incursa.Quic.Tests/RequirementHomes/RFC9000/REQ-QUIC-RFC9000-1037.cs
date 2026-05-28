// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-1037">After the client has received and processed an Initial or Retry packet from the server, it MUST discard any subsequent Retry packets that it receives.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-1037")]
public sealed class REQ_QUIC_RFC9000_1037
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-1037">After the client has received and processed an Initial or Retry packet from the server, it MUST discard any subsequent Retry packets that it receives.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-1037")]
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
    [Requirement("REQ-QUIC-RFC9000-1037")]
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
    [Requirement("REQ-QUIC-RFC9000-1037")]
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
}
