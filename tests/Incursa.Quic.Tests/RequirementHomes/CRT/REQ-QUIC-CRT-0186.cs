// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests.RequirementHomes.CRT;

[Requirement("REQ-QUIC-CRT-0186")]
public sealed class REQ_QUIC_CRT_0186
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void UsefulWorkVectorPreservesUnlikeDispatchComponents()
    {
        QuicActorServiceObservation observation = new(
            ServiceSequence: 1,
            ShardIndex: 2,
            WakeSequence: 3,
            WakePosition: 4,
            QuicActorWakeCompletion.Synchronous,
            QuicActorWakeSource.Inbox,
            QuicActorWorkKind.StreamWrite,
            QuicActorServiceDisposition.Completed,
            QueueDelayMicros: 5,
            ServiceTimeMicros: 6,
            PendingWorkItemsAfterDequeue: 7,
            EffectCount: 8,
            ApplicationSendFollowOnCount: 9,
            FlowControlFollowOnCount: 10,
            StreamCapacityFollowOnCount: 11,
            QuicConnectionPhase.Active,
            DisposalStarted: false,
            QuicActorServiceValidity.UsefulWorkUnitsUndefined);

        QuicActorUsefulWorkVector vector =
            QuicActorUsefulWorkVector.FromObservation(in observation);

        Assert.Equal(QuicActorWorkKind.StreamWrite, vector.WorkKind);
        Assert.Equal(1U, vector.DispatchCount);
        Assert.Equal(8U, vector.EffectCount);
        Assert.Equal(9U, vector.ApplicationSendFollowOnCount);
        Assert.Equal(10U, vector.FlowControlFollowOnCount);
        Assert.Equal(11U, vector.StreamCapacityFollowOnCount);
        Assert.Equal(6UL, vector.ServiceTimeMicros);
        Assert.Equal(5UL, vector.QueueDelayMicros);
        Assert.Equal(
            "quic-actor-useful-work-vector-v1",
            QuicActorUsefulWorkVector.CurrentContractVersion);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void IdleRequestOwnsOneExactPostGeneration()
    {
        QuicActorContinuationRepostGate gate = new();

        Assert.True(gate.TryRequest(out QuicActorContinuationRepostToken token));
        Assert.Equal(1UL, token.Generation);
        Assert.False(gate.TryRequest(out _));
        Assert.Equal(
            new QuicActorContinuationRepostSnapshot(
                QuicActorContinuationRepostState.Posted,
                1),
            gate.Snapshot);
        Assert.True(gate.TryBeginService(token));
        Assert.False(gate.TryBeginService(token));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ConcurrentServiceRequestCoalescesIntoOneRepost()
    {
        QuicActorContinuationRepostGate gate = new();
        Assert.True(gate.TryRequest(out QuicActorContinuationRepostToken first));
        Assert.True(gate.TryBeginService(first));

        Assert.False(gate.TryRequest(out _));
        Assert.False(gate.TryRequest(out _));
        Assert.Equal(
            QuicActorContinuationRepostState.RepostRequested,
            gate.Snapshot.State);

        Assert.True(gate.TryCompleteService(
            first,
            hasRemainingWork: false,
            out QuicActorContinuationRepostToken second));
        Assert.Equal(2UL, second.Generation);
        Assert.Equal(
            QuicActorContinuationRepostState.Posted,
            gate.Snapshot.State);
        Assert.True(gate.TryBeginService(second));
        Assert.False(gate.TryCompleteService(
            second,
            hasRemainingWork: false,
            out QuicActorContinuationRepostToken none));
        Assert.True(none.IsEmpty);
        Assert.Equal(
            QuicActorContinuationRepostState.Idle,
            gate.Snapshot.State);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ExactRemainingWorkSignalCreatesOneNewGeneration()
    {
        QuicActorContinuationRepostGate gate = new();
        Assert.True(gate.TryRequest(out QuicActorContinuationRepostToken first));
        Assert.True(gate.TryBeginService(first));

        Assert.True(gate.TryCompleteService(
            first,
            hasRemainingWork: true,
            out QuicActorContinuationRepostToken second));
        Assert.Equal(first.Generation + 1, second.Generation);
        Assert.True(gate.TryBeginService(second));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void StaleAndDuplicateTokensCannotChangeState()
    {
        QuicActorContinuationRepostGate gate = new();
        Assert.True(gate.TryRequest(out QuicActorContinuationRepostToken first));
        QuicActorContinuationRepostToken stale =
            new(first.Generation + 1);

        Assert.False(gate.TryBeginService(stale));
        Assert.False(gate.TryCompleteService(
            stale,
            hasRemainingWork: true,
            out _));
        Assert.False(gate.TryAbandonPosted(stale));
        Assert.Equal(
            QuicActorContinuationRepostState.Posted,
            gate.Snapshot.State);

        Assert.True(gate.TryBeginService(first));
        Assert.False(gate.TryBeginService(first));
        Assert.False(gate.TryAbandonPosted(first));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void FailedPostAndStopFailClosed()
    {
        QuicActorContinuationRepostGate gate = new();
        Assert.True(gate.TryRequest(out QuicActorContinuationRepostToken token));
        Assert.True(gate.TryAbandonPosted(token));
        Assert.Equal(
            QuicActorContinuationRepostState.Stopped,
            gate.Snapshot.State);
        Assert.False(gate.TryRequest(out _));
        Assert.False(gate.TryBeginService(token));

        QuicActorContinuationRepostGate servicing = new();
        Assert.True(servicing.TryRequest(out token));
        Assert.True(servicing.TryBeginService(token));
        servicing.Stop();
        Assert.False(servicing.TryCompleteService(
            token,
            hasRemainingWork: true,
            out _));
        Assert.False(servicing.TryRequest(out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ConcurrentRequestsHaveOneEnqueueOwner()
    {
        QuicActorContinuationRepostGate gate = new();
        var enqueueOwners = 0;

        Parallel.For(
            0,
            128,
            iteration =>
            {
                if (gate.TryRequest(out _))
                {
                    Interlocked.Increment(ref enqueueOwners);
                }
            });

        Assert.Equal(1, enqueueOwners);
        Assert.Equal(
            QuicActorContinuationRepostState.Posted,
            gate.Snapshot.State);
        Assert.Equal(1UL, gate.Snapshot.Generation);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void BoundedStatefulSequencesMatchReferenceTransitions()
    {
        Random random = new(0x186);
        for (var sequence = 0; sequence < 128; sequence++)
        {
            QuicActorContinuationRepostGate gate = new();
            QuicActorContinuationRepostState expectedState =
                QuicActorContinuationRepostState.Idle;
            ulong expectedGeneration = 0;

            for (var step = 0; step < 128; step++)
            {
                int operation = random.Next(
                    step < 120 ? 4 : 5);
                bool useExactToken = random.Next(2) == 0;
                QuicActorContinuationRepostToken candidate = new(
                    useExactToken
                        ? expectedGeneration
                        : expectedGeneration + 1);
                switch (operation)
                {
                    case 0:
                        bool expectedRequest =
                            expectedState
                                == QuicActorContinuationRepostState.Idle;
                        bool requested = gate.TryRequest(
                            out QuicActorContinuationRepostToken requestedToken);
                        Assert.Equal(expectedRequest, requested);
                        if (expectedRequest)
                        {
                            expectedGeneration++;
                            expectedState =
                                QuicActorContinuationRepostState.Posted;
                            Assert.Equal(
                                expectedGeneration,
                                requestedToken.Generation);
                        }
                        else if (expectedState
                            == QuicActorContinuationRepostState.Servicing)
                        {
                            expectedState =
                                QuicActorContinuationRepostState.RepostRequested;
                        }

                        break;

                    case 1:
                        bool expectedBegin =
                            expectedState
                                == QuicActorContinuationRepostState.Posted
                            && useExactToken
                            && expectedGeneration != 0;
                        Assert.Equal(
                            expectedBegin,
                            gate.TryBeginService(candidate));
                        if (expectedBegin)
                        {
                            expectedState =
                                QuicActorContinuationRepostState.Servicing;
                        }

                        break;

                    case 2:
                        bool hasRemainingWork = random.Next(2) == 0;
                        bool exactCompletion =
                            expectedState is (
                                QuicActorContinuationRepostState.Servicing
                                or QuicActorContinuationRepostState.RepostRequested)
                            && useExactToken
                            && expectedGeneration != 0;
                        bool expectedRepost =
                            exactCompletion
                            && (hasRemainingWork
                                || expectedState
                                    == QuicActorContinuationRepostState.RepostRequested);
                        bool reposted = gate.TryCompleteService(
                            candidate,
                            hasRemainingWork,
                            out QuicActorContinuationRepostToken repostToken);
                        Assert.Equal(expectedRepost, reposted);
                        if (expectedRepost)
                        {
                            expectedGeneration++;
                            expectedState =
                                QuicActorContinuationRepostState.Posted;
                            Assert.Equal(
                                expectedGeneration,
                                repostToken.Generation);
                        }
                        else if (exactCompletion)
                        {
                            expectedState =
                                QuicActorContinuationRepostState.Idle;
                        }

                        break;

                    case 3:
                        bool expectedAbandon =
                            expectedState
                                == QuicActorContinuationRepostState.Posted
                            && useExactToken
                            && expectedGeneration != 0;
                        Assert.Equal(
                            expectedAbandon,
                            gate.TryAbandonPosted(candidate));
                        if (expectedAbandon)
                        {
                            expectedState =
                                QuicActorContinuationRepostState.Stopped;
                        }

                        break;

                    case 4:
                        gate.Stop();
                        expectedState =
                            QuicActorContinuationRepostState.Stopped;
                        break;
                }

                Assert.Equal(
                    new QuicActorContinuationRepostSnapshot(
                        expectedState,
                        expectedGeneration),
                    gate.Snapshot);
            }
        }
    }
}
