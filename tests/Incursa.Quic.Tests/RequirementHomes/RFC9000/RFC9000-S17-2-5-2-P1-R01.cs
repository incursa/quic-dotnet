// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S17-2-5-2-P1-R01">A client MUST accept and process at most one Retry packet for each connection attempt.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S17-2-5-2-P1-R01")]
public sealed class REQ_QUIC_RFC9000_1036
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="RFC9000-S17-2-5-2-P1-R01">A client MUST accept and process at most one Retry packet for each connection attempt.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("RFC9000-S17-2-5-2-P1-R01")]
    public void ClientAcceptsAndProcessesTheFirstRetryPacketForAConnectionAttempt()
    {
        QuicConnectionRuntime runtime = QuicS17P2P5P2TestSupport.CreateBootstrappedClientRuntime();
        QuicConnectionRetryReceivedEvent retryReceivedEvent = QuicS17P2P5P2TestSupport.CreateRetryReceivedEvent(1);

        QuicConnectionTransitionResult retryResult = runtime.Transition(retryReceivedEvent, nowTicks: 1);

        Assert.True(retryResult.StateChanged);
        Assert.Contains(retryResult.Effects, effect => effect is QuicConnectionSendDatagramEffect);
        Assert.Equal(QuicConnectionPhase.Establishing, runtime.Phase);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [Requirement("RFC9000-S17-2-5-2-P1-R01")]
    public void ClientRejectsRetryPacketsMissingRequiredSourceConnectionIdOrToken()
    {
        QuicConnectionRuntime runtime = QuicS17P2P5P2TestSupport.CreateBootstrappedClientRuntime();

        QuicConnectionTransitionResult missingSourceResult = runtime.Transition(
            new QuicConnectionRetryReceivedEvent(
                ObservedAtTicks: 1,
                RetrySourceConnectionId: ReadOnlyMemory<byte>.Empty,
                RetryToken: QuicS17P2P5P2TestSupport.RetryToken),
            nowTicks: 1);

        QuicConnectionTransitionResult missingTokenResult = runtime.Transition(
            new QuicConnectionRetryReceivedEvent(
                ObservedAtTicks: 2,
                RetrySourceConnectionId: QuicS17P2P5P2TestSupport.RetrySourceConnectionId,
                RetryToken: ReadOnlyMemory<byte>.Empty),
            nowTicks: 2);

        Assert.False(missingSourceResult.StateChanged);
        Assert.Empty(missingSourceResult.Effects);
        Assert.False(missingTokenResult.StateChanged);
        Assert.Empty(missingTokenResult.Effects);
        Assert.Equal(QuicConnectionPhase.Establishing, runtime.Phase);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    [Requirement("RFC9000-S17-2-5-2-P1-R01")]
    [Requirement("RFC9000-S17-2-5-2-P3-R01")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P5P2-0006")]
    public void ClientProcessesRetryWithMaximumSourceConnectionIdAndMinimumToken()
    {
        QuicConnectionRuntime runtime = QuicS17P2P5P2TestSupport.CreateBootstrappedClientRuntime();

        QuicConnectionTransitionResult retryResult = runtime.Transition(
            QuicS17P2P5P2TestSupport.CreateRetryReceivedEvent(
                1,
                QuicS17P2P5P2TestSupport.MaximumLengthRetrySourceConnectionId,
                QuicS17P2P5P2TestSupport.SingleByteRetryToken),
            nowTicks: 1);

        QuicS17P2P5P3TestSupport.RetryReplayInitialPacket replayPacket =
            QuicS17P2P5P2TestSupport.ReadSingleRetryReplayInitialPacket(
                retryResult,
                QuicS17P2P5P2TestSupport.MaximumLengthRetrySourceConnectionId);

        Assert.True(retryResult.StateChanged);
        Assert.Equal(QuicS17P2P5P2TestSupport.MaximumLengthRetrySourceConnectionId, replayPacket.DestinationConnectionId);
        Assert.Equal(QuicS17P2P5P2TestSupport.SingleByteRetryToken, replayPacket.Token);
        Assert.Equal(QuicConnectionPhase.Establishing, runtime.Phase);
    }
}
