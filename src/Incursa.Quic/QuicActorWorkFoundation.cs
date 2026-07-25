// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

/// <summary>
/// Preserves the unlike bounded components of one actor dispatch without
/// claiming that they are interchangeable scalar work units.
/// </summary>
internal readonly record struct QuicActorUsefulWorkVector(
    QuicActorWorkKind WorkKind,
    uint DispatchCount,
    uint EffectCount,
    uint ApplicationSendFollowOnCount,
    uint FlowControlFollowOnCount,
    uint StreamCapacityFollowOnCount,
    ulong ServiceTimeMicros,
    ulong? QueueDelayMicros)
{
    internal const string CurrentContractVersion =
        "quic-actor-useful-work-vector-v1";

    internal static QuicActorUsefulWorkVector FromObservation(
        in QuicActorServiceObservation observation)
        => new(
            observation.WorkKind,
            DispatchCount: 1,
            observation.EffectCount,
            observation.ApplicationSendFollowOnCount,
            observation.FlowControlFollowOnCount,
            observation.StreamCapacityFollowOnCount,
            observation.ServiceTimeMicros,
            observation.QueueDelayMicros);
}

internal enum QuicActorContinuationAssessmentState : byte
{
    NotAssessed = 0,
    Drained = 1,
    Scheduled = 2,
    Blocked = 3,
    ReadyAfterCooperativeYield = 4,
    Invalid = 5,
}

/// <summary>
/// Preserves exact per-producer continuation state after one actor dispatch.
/// Pending counts are not runnable or continuation-ready unless the matching
/// state explicitly says <see cref="QuicActorContinuationAssessmentState.ReadyAfterCooperativeYield"/>.
/// </summary>
internal readonly record struct QuicActorContinuationAssessment(
    QuicActorContinuationAssessmentState ApplicationSendState,
    uint? ApplicationSendRemainingCount,
    QuicActorContinuationAssessmentState FlowControlState,
    uint? FlowControlRemainingCount,
    QuicActorContinuationAssessmentState StreamCapacityState,
    uint? StreamCapacityRemainingCount)
{
    internal const string CurrentContractVersion =
        "quic-actor-continuation-assessment-v1";

    internal bool IsComplete =>
        IsAssessed(ApplicationSendState)
        && IsAssessed(FlowControlState)
        && IsAssessed(StreamCapacityState);

    internal bool HasReadyContinuation =>
        ApplicationSendState
            == QuicActorContinuationAssessmentState
                .ReadyAfterCooperativeYield
        || FlowControlState
            == QuicActorContinuationAssessmentState
                .ReadyAfterCooperativeYield
        || StreamCapacityState
            == QuicActorContinuationAssessmentState
                .ReadyAfterCooperativeYield;

    internal bool HasInvalidState =>
        ApplicationSendState
            == QuicActorContinuationAssessmentState.Invalid
        || FlowControlState
            == QuicActorContinuationAssessmentState.Invalid
        || StreamCapacityState
            == QuicActorContinuationAssessmentState.Invalid;

    public string ContractVersion => CurrentContractVersion;

    internal static bool IsConsistent(
        QuicActorContinuationAssessmentState state,
        uint? remainingCount)
        => state switch
        {
            QuicActorContinuationAssessmentState.NotAssessed
                or QuicActorContinuationAssessmentState.Invalid
                => !remainingCount.HasValue,
            QuicActorContinuationAssessmentState.Drained
                => remainingCount == 0,
            QuicActorContinuationAssessmentState.Scheduled
                or QuicActorContinuationAssessmentState.Blocked
                or QuicActorContinuationAssessmentState
                    .ReadyAfterCooperativeYield
                => remainingCount is > 0,
            _ => false,
        };

    private static bool IsAssessed(
        QuicActorContinuationAssessmentState state)
        => state is not (
            QuicActorContinuationAssessmentState.NotAssessed
            or QuicActorContinuationAssessmentState.Invalid);
}

internal enum QuicActorContinuationRepostState : byte
{
    Idle = 0,
    Posted = 1,
    Servicing = 2,
    RepostRequested = 3,
    Stopped = 4,
}

internal readonly record struct QuicActorContinuationRepostToken(
    ulong Generation)
{
    internal bool IsEmpty => Generation == 0;
}

internal readonly record struct QuicActorContinuationRepostSnapshot(
    QuicActorContinuationRepostState State,
    ulong Generation);

/// <summary>
/// Coalesces connection-local continuation requests into an exactly-once
/// generation token. This primitive does not enqueue work or decide whether
/// protocol work may yield.
/// </summary>
/// <remarks>
/// A future actor quantum may own one gate per connection. The caller remains
/// responsible for supplying an exact remaining-work signal, enqueuing a
/// returned token once, and abandoning the gate if that enqueue cannot be
/// completed. Stopping or abandoning fails closed.
/// </remarks>
internal sealed class QuicActorContinuationRepostGate
{
    private const int StateBitCount = 3;
    private const long StateMask = (1L << StateBitCount) - 1;
    private const ulong MaximumGeneration =
        (1UL << (sizeof(long) * 8 - StateBitCount - 1)) - 1;

    private long packedState;

    internal QuicActorContinuationRepostSnapshot Snapshot
    {
        get
        {
            long current = Volatile.Read(ref packedState);
            return new(
                GetState(current),
                GetGeneration(current));
        }
    }

    /// <summary>
    /// Requests one continuation post. A true result makes this caller the
    /// sole owner of the returned generation's enqueue.
    /// </summary>
    internal bool TryRequest(
        out QuicActorContinuationRepostToken token)
    {
        while (true)
        {
            long current = Volatile.Read(ref packedState);
            QuicActorContinuationRepostState state = GetState(current);
            ulong generation = GetGeneration(current);
            switch (state)
            {
                case QuicActorContinuationRepostState.Idle:
                    if (!TryGetNextGeneration(
                            generation,
                            out ulong nextGeneration))
                    {
                        TryStopAt(current, generation);
                        token = default;
                        return false;
                    }

                    long posted = Pack(
                        nextGeneration,
                        QuicActorContinuationRepostState.Posted);
                    if (Interlocked.CompareExchange(
                            ref packedState,
                            posted,
                            current) == current)
                    {
                        token = new(nextGeneration);
                        return true;
                    }

                    break;

                case QuicActorContinuationRepostState.Servicing:
                    long requested = Pack(
                        generation,
                        QuicActorContinuationRepostState.RepostRequested);
                    if (Interlocked.CompareExchange(
                            ref packedState,
                            requested,
                            current) == current)
                    {
                        token = default;
                        return false;
                    }

                    break;

                case QuicActorContinuationRepostState.Posted:
                case QuicActorContinuationRepostState.RepostRequested:
                case QuicActorContinuationRepostState.Stopped:
                    token = default;
                    return false;

                default:
                    throw new InvalidOperationException(
                        "The actor continuation repost gate has an invalid state.");
            }
        }
    }

    /// <summary>
    /// Claims the exact posted generation for service. Stale or duplicate
    /// tokens cannot begin service.
    /// </summary>
    internal bool TryBeginService(
        QuicActorContinuationRepostToken token)
    {
        if (token.IsEmpty)
        {
            return false;
        }

        long posted = Pack(
            token.Generation,
            QuicActorContinuationRepostState.Posted);
        long servicing = Pack(
            token.Generation,
            QuicActorContinuationRepostState.Servicing);
        return Interlocked.CompareExchange(
            ref packedState,
            servicing,
            posted) == posted;
    }

    /// <summary>
    /// Completes the exact servicing generation at a reviewed cooperative
    /// boundary. Remaining work or a concurrent request creates one new
    /// posted generation; otherwise the gate becomes idle.
    /// </summary>
    internal bool TryCompleteService(
        QuicActorContinuationRepostToken token,
        bool hasRemainingWork,
        out QuicActorContinuationRepostToken repostToken)
    {
        if (token.IsEmpty)
        {
            repostToken = default;
            return false;
        }

        while (true)
        {
            long current = Volatile.Read(ref packedState);
            ulong generation = GetGeneration(current);
            QuicActorContinuationRepostState state = GetState(current);
            if (generation != token.Generation
                || state is not (
                    QuicActorContinuationRepostState.Servicing
                    or QuicActorContinuationRepostState.RepostRequested))
            {
                repostToken = default;
                return false;
            }

            bool shouldRepost =
                hasRemainingWork
                || state
                    == QuicActorContinuationRepostState.RepostRequested;
            if (!shouldRepost)
            {
                long idle = Pack(
                    generation,
                    QuicActorContinuationRepostState.Idle);
                if (Interlocked.CompareExchange(
                        ref packedState,
                        idle,
                        current) == current)
                {
                    repostToken = default;
                    return false;
                }

                continue;
            }

            if (!TryGetNextGeneration(
                    generation,
                    out ulong nextGeneration))
            {
                TryStopAt(current, generation);
                repostToken = default;
                return false;
            }

            long posted = Pack(
                nextGeneration,
                QuicActorContinuationRepostState.Posted);
            if (Interlocked.CompareExchange(
                    ref packedState,
                    posted,
                    current) == current)
            {
                repostToken = new(nextGeneration);
                return true;
            }
        }
    }

    /// <summary>
    /// Fails closed when the sole owner of a posted token cannot enqueue it.
    /// A posted generation cannot safely return to idle because another
    /// requester may already have observed and coalesced with it.
    /// </summary>
    internal bool TryAbandonPosted(
        QuicActorContinuationRepostToken token)
    {
        if (token.IsEmpty)
        {
            return false;
        }

        long posted = Pack(
            token.Generation,
            QuicActorContinuationRepostState.Posted);
        long stopped = Pack(
            token.Generation,
            QuicActorContinuationRepostState.Stopped);
        return Interlocked.CompareExchange(
            ref packedState,
            stopped,
            posted) == posted;
    }

    internal void Stop()
    {
        while (true)
        {
            long current = Volatile.Read(ref packedState);
            if (GetState(current)
                == QuicActorContinuationRepostState.Stopped)
            {
                return;
            }

            long stopped = Pack(
                GetGeneration(current),
                QuicActorContinuationRepostState.Stopped);
            if (Interlocked.CompareExchange(
                    ref packedState,
                    stopped,
                    current) == current)
            {
                return;
            }
        }
    }

    private void TryStopAt(long expected, ulong generation)
    {
        _ = Interlocked.CompareExchange(
            ref packedState,
            Pack(
                generation,
                QuicActorContinuationRepostState.Stopped),
            expected);
    }

    private static bool TryGetNextGeneration(
        ulong generation,
        out ulong nextGeneration)
    {
        if (generation >= MaximumGeneration)
        {
            nextGeneration = 0;
            return false;
        }

        nextGeneration = generation + 1;
        return true;
    }

    private static long Pack(
        ulong generation,
        QuicActorContinuationRepostState state)
    {
        if (generation > MaximumGeneration)
        {
            throw new ArgumentOutOfRangeException(nameof(generation));
        }

        return checked(
            (long)(generation << StateBitCount)
            | (byte)state);
    }

    private static ulong GetGeneration(long packed)
        => unchecked((ulong)packed) >> StateBitCount;

    private static QuicActorContinuationRepostState GetState(long packed)
        => (QuicActorContinuationRepostState)(packed & StateMask);
}
