// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Diagnostics;

namespace Incursa.Quic;

internal readonly record struct QuicAdaptiveRuntimeUnifiedEpochEvidence(
    QuicAdaptiveRuntimeConnectionObservation ConnectionObservation,
    QuicReceiveCreditPolicySnapshot ReceiveCreditSnapshot,
    QuicAdaptiveRuntimePostServiceBoundary PostServiceBoundary,
    QuicAdaptiveRuntimeStage1EpochEvidence Stage1,
    QuicActorServiceEpochSummary ActorService,
    QuicBufferCopyEpochSummary BufferCopy)
{
    internal const string CurrentEvidenceContractVersion =
        "adaptive-runtime-unified-epoch-evidence-v7";

    public string EvidenceContractVersion =>
        CurrentEvidenceContractVersion;

    public ulong ConnectionEpochSequence =>
        ConnectionObservation.ConnectionEpochSequence;
}

internal interface IQuicAdaptiveRuntimeUnifiedEpochEvidenceSink
{
    bool TryPublish(in QuicAdaptiveRuntimeUnifiedEpochEvidence evidence);
}

/// <summary>
/// Collects the bounded Stage 1 and Stage 2 observation streams and seals them
/// together only when the runtime reaches its versioned post-service boundary.
/// </summary>
internal sealed class QuicAdaptiveRuntimeUnifiedEpochEvidenceAccumulator :
    IQuicAdaptiveRuntimeShadowEpochSink,
    IQuicApplicationSendTurnEvidenceSink,
    IQuicApplicationSendBatchEvidenceSink,
    IQuicQueuedSendBurstEvidenceSink,
    IQuicOversizedWriteAdmissionEvidenceSink,
    IQuicActorServiceEvidenceSink,
    IQuicBufferCopyEvidenceSink
{
    private const ulong MicrosPerSecond = 1_000_000UL;
    private readonly object gate = new();
    private readonly QuicAdaptiveRuntimeStage1EvidenceAccumulator stage1;
    private readonly QuicActorServiceEpochAccumulator actorService = new();
    private readonly QuicBufferCopyEpochAccumulator bufferCopy;
    private readonly IQuicAdaptiveRuntimeUnifiedEpochEvidenceSink sink;
    private bool hasEpochOrigin;
    private long epochOriginTicks;
    private ulong lastEpochSequence;

    internal QuicAdaptiveRuntimeUnifiedEpochEvidenceAccumulator(
        in QuicAdaptiveRuntimeStage1PolicySnapshot configuredStage1Policy,
        IQuicAdaptiveRuntimeUnifiedEpochEvidenceSink sink)
        : this(
            in configuredStage1Policy,
            QuicBufferCopyPolicy.CreateConfiguredSnapshot(
                QuicBufferCopyObservationMode.Disabled,
                forcedValue: null),
            sink)
    {
    }

    internal QuicAdaptiveRuntimeUnifiedEpochEvidenceAccumulator(
        in QuicAdaptiveRuntimeStage1PolicySnapshot configuredStage1Policy,
        in QuicBufferCopyConfiguredPolicySnapshot configuredBufferCopyPolicy,
        IQuicAdaptiveRuntimeUnifiedEpochEvidenceSink sink)
    {
        ArgumentNullException.ThrowIfNull(sink);
        stage1 = new(in configuredStage1Policy);
        bufferCopy = new(in configuredBufferCopyPolicy);
        this.sink = sink;
    }

    public bool TryPublish(in QuicApplicationSendTurnEvidence evidence)
    {
        lock (gate)
        {
            return stage1.TryPublish(in evidence);
        }
    }

    public bool TryPublish(in QuicApplicationSendBatchEvidence evidence)
    {
        lock (gate)
        {
            return stage1.TryPublish(in evidence);
        }
    }

    public bool TryPublish(in QuicQueuedSendBurstEvidence evidence)
    {
        lock (gate)
        {
            return stage1.TryPublish(in evidence);
        }
    }

    public bool TryPublish(in QuicOversizedWriteAdmissionEvidence evidence)
    {
        lock (gate)
        {
            return stage1.TryPublish(in evidence);
        }
    }

    public bool TryPublish(in QuicActorServiceObservation observation)
    {
        lock (gate)
        {
            return actorService.TryPublish(in observation);
        }
    }

    public bool TryPublish(in QuicBufferCopyObservation observation)
    {
        lock (gate)
        {
            return bufferCopy.TryPublish(in observation);
        }
    }

    public bool TryPublish(
        in QuicAdaptiveRuntimeConnectionObservation observation,
        in QuicReceiveCreditPolicySnapshot snapshot,
        in QuicAdaptiveRuntimePostServiceBoundary boundary)
    {
        lock (gate)
        {
            ulong epochSequence = observation.ConnectionEpochSequence;
            if (epochSequence == 0
                || epochSequence <= lastEpochSequence
                || snapshot.EpochSequence != epochSequence
                || boundary.ConnectionEpochSequence != epochSequence
                || boundary.EpochEndTicks != observation.EpochEndTicks
                || observation.EpochEndTicks <= observation.EpochStartTicks)
            {
                return false;
            }

            if (!hasEpochOrigin)
            {
                epochOriginTicks = observation.EpochStartTicks;
                hasEpochOrigin = true;
            }

            if (observation.EpochStartTicks < epochOriginTicks)
            {
                return false;
            }

            ulong epochStartOffsetMicros = ConvertTicksToMicros(
                observation.EpochStartTicks - epochOriginTicks);
            ulong epochDurationMicros = Math.Max(
                1UL,
                observation.ActiveDurationMicros);
            QuicAdaptiveRuntimeStage1EpochEvidence stage1Evidence =
                stage1.CaptureEpoch(
                    epochSequence,
                    epochStartOffsetMicros,
                    epochDurationMicros);
            QuicActorServiceEpochSummary actorServiceEvidence =
                actorService.CaptureAndReset();
            QuicBufferCopyEpochSummary bufferCopyEvidence =
                bufferCopy.CaptureAndReset();
            QuicAdaptiveRuntimeUnifiedEpochEvidence unified = new(
                observation,
                snapshot,
                boundary,
                stage1Evidence,
                actorServiceEvidence,
                bufferCopyEvidence);

            lastEpochSequence = epochSequence;
            return sink.TryPublish(in unified);
        }
    }

    private static ulong ConvertTicksToMicros(long ticks)
    {
        if (ticks <= 0)
        {
            return 0;
        }

        ulong positiveTicks = (ulong)ticks;
        ulong frequency = (ulong)Stopwatch.Frequency;
        ulong wholeSeconds = positiveTicks / frequency;
        ulong remainingTicks = positiveTicks % frequency;
        if (wholeSeconds > ulong.MaxValue / MicrosPerSecond)
        {
            return ulong.MaxValue;
        }

        ulong wholeMicros = wholeSeconds * MicrosPerSecond;
        ulong partialMicros = (remainingTicks * MicrosPerSecond) / frequency;
        return ulong.MaxValue - wholeMicros < partialMicros
            ? ulong.MaxValue
            : wholeMicros + partialMicros;
    }
}
