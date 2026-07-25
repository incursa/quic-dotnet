// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Diagnostics;

namespace Incursa.Quic;

internal readonly record struct QuicConnectionShardPlacementEpochSummary(
    QuicConnectionShardPlacementDecision Decision,
    bool HasDecision,
    ulong EventCount);

internal readonly record struct
    QuicApplicationDatagramBatchTransportEpochSummary(
        QuicApplicationDatagramBatchTransportConfiguredPolicySnapshot
            ConfiguredSnapshot,
        QuicApplicationDatagramBatchTransportCapability Capability,
        QuicApplicationDatagramBatchTransportDecision LastDecision,
        bool HasConfiguredSnapshot,
        bool HasCapability,
        bool HasDecision,
        ulong CapabilityEventCount,
        ulong DecisionEventCount,
        ulong SegmentedDecisionCount,
        ulong OrdinaryDecisionCount,
        ulong SocketCallCount,
        ulong OrdinarySocketCallCount,
        ulong SegmentedSocketCallCount,
        ulong DatagramCount,
        ulong SegmentCount,
        ulong SubmittedBytes,
        ulong AcceptedBytes,
        ulong FailedSocketCallCount,
        ulong PartialSendCount,
        ulong LifecycleGuardCount);

internal readonly record struct QuicCongestionPacingProfileEpochSummary(
    QuicCongestionPacingProfileDecision Decision,
    bool HasDecision,
    ulong EventCount);

internal readonly record struct QuicAdaptiveRuntimeUnifiedEpochEvidence(
    QuicAdaptiveRuntimeConnectionObservation ConnectionObservation,
    QuicReceiveCreditPolicySnapshot ReceiveCreditSnapshot,
    QuicAdaptiveRuntimePostServiceBoundary PostServiceBoundary,
    QuicAdaptiveRuntimeStage1EpochEvidence Stage1,
    QuicActorServiceEpochSummary ActorService,
    QuicBufferCopyEpochSummary BufferCopy,
    QuicAdaptiveBackpressureEpochSummary AdaptiveBackpressure,
    QuicPacketFlushCadenceEpochSummary PacketFlushCadence,
    QuicReceiveDeliveryQuantumEpochSummary ReceiveDeliveryQuantum,
    QuicConnectionShardPlacementEpochSummary ConnectionShardPlacement,
    QuicApplicationDatagramBatchTransportEpochSummary
        ApplicationDatagramBatchTransport,
    QuicCongestionPacingProfileEpochSummary CongestionPacingProfile)
{
    internal const string CurrentEvidenceContractVersion =
        "adaptive-runtime-unified-epoch-evidence-v13";

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
    IQuicBufferCopyEvidenceSink,
    IQuicAdaptiveBackpressureEvidenceSink,
    IQuicPacketFlushCadenceEvidenceSink,
    IQuicReceiveDeliveryQuantumEvidenceSink,
    IQuicConnectionShardPlacementEvidenceSink,
    IQuicApplicationDatagramBatchTransportEvidenceSink,
    IQuicCongestionPacingProfileEvidenceSink
{
    private const ulong MicrosPerSecond = 1_000_000UL;
    private readonly object gate = new();
    private readonly QuicAdaptiveRuntimeStage1EvidenceAccumulator stage1;
    private readonly QuicActorServiceEpochAccumulator actorService = new();
    private readonly QuicBufferCopyEpochAccumulator bufferCopy;
    private readonly QuicAdaptiveBackpressureEpochAccumulator
        adaptiveBackpressure;
    private readonly QuicPacketFlushCadenceEpochAccumulator
        packetFlushCadence;
    private readonly QuicReceiveDeliveryQuantumEpochAccumulator
        receiveDeliveryQuantum;
    private readonly IQuicAdaptiveRuntimeUnifiedEpochEvidenceSink sink;
    private bool hasEpochOrigin;
    private long epochOriginTicks;
    private ulong lastEpochSequence;
    private QuicConnectionShardPlacementDecision
        connectionShardPlacementDecision;
    private bool hasConnectionShardPlacementDecision;
    private QuicApplicationDatagramBatchTransportConfiguredPolicySnapshot
        applicationDatagramBatchTransportConfiguredSnapshot;
    private QuicApplicationDatagramBatchTransportCapability
        applicationDatagramBatchTransportCapability;
    private QuicApplicationDatagramBatchTransportDecision
        applicationDatagramBatchTransportLastDecision;
    private bool
        hasApplicationDatagramBatchTransportConfiguredSnapshot;
    private bool hasApplicationDatagramBatchTransportCapability;
    private bool hasApplicationDatagramBatchTransportDecision;
    private ulong applicationDatagramBatchTransportCapabilityEventCount;
    private ulong applicationDatagramBatchTransportDecisionEventCount;
    private ulong applicationDatagramBatchTransportSegmentedDecisionCount;
    private ulong applicationDatagramBatchTransportOrdinaryDecisionCount;
    private ulong applicationDatagramBatchTransportSocketCallCount;
    private ulong applicationDatagramBatchTransportOrdinarySocketCallCount;
    private ulong applicationDatagramBatchTransportSegmentedSocketCallCount;
    private ulong applicationDatagramBatchTransportDatagramCount;
    private ulong applicationDatagramBatchTransportSegmentCount;
    private ulong applicationDatagramBatchTransportSubmittedBytes;
    private ulong applicationDatagramBatchTransportAcceptedBytes;
    private ulong applicationDatagramBatchTransportFailedSocketCallCount;
    private ulong applicationDatagramBatchTransportPartialSendCount;
    private ulong applicationDatagramBatchTransportLifecycleGuardCount;
    private QuicCongestionPacingProfileDecision
        congestionPacingProfileDecision;
    private bool hasCongestionPacingProfileDecision;

    internal QuicAdaptiveRuntimeUnifiedEpochEvidenceAccumulator(
        in QuicAdaptiveRuntimeStage1PolicySnapshot configuredStage1Policy,
        IQuicAdaptiveRuntimeUnifiedEpochEvidenceSink sink)
        : this(
            in configuredStage1Policy,
            QuicBufferCopyPolicy.CreateConfiguredSnapshot(
                QuicBufferCopyObservationMode.Disabled,
                forcedValue: null),
            QuicAdaptiveBackpressurePolicy.CreateConfiguredSnapshot(
                QuicAdaptiveBackpressureObservationMode.Disabled,
                forcedValue: null),
            QuicPacketFlushCadencePolicy.CreateConfiguredSnapshot(
                QuicPacketFlushCadenceObservationMode.Disabled,
                forcedValue: null),
            QuicReceiveDeliveryQuantumPolicy.CreateConfiguredSnapshot(
                QuicReceiveDeliveryQuantumObservationMode.Disabled,
                forcedValue: null),
            sink)
    {
    }

    internal QuicAdaptiveRuntimeUnifiedEpochEvidenceAccumulator(
        in QuicAdaptiveRuntimeStage1PolicySnapshot configuredStage1Policy,
        in QuicBufferCopyConfiguredPolicySnapshot configuredBufferCopyPolicy,
        IQuicAdaptiveRuntimeUnifiedEpochEvidenceSink sink)
        : this(
            in configuredStage1Policy,
            in configuredBufferCopyPolicy,
            QuicAdaptiveBackpressurePolicy.CreateConfiguredSnapshot(
                QuicAdaptiveBackpressureObservationMode.Disabled,
                forcedValue: null),
            QuicPacketFlushCadencePolicy.CreateConfiguredSnapshot(
                QuicPacketFlushCadenceObservationMode.Disabled,
                forcedValue: null),
            QuicReceiveDeliveryQuantumPolicy.CreateConfiguredSnapshot(
                QuicReceiveDeliveryQuantumObservationMode.Disabled,
                forcedValue: null),
            sink)
    {
    }

    internal QuicAdaptiveRuntimeUnifiedEpochEvidenceAccumulator(
        in QuicAdaptiveRuntimeStage1PolicySnapshot configuredStage1Policy,
        in QuicBufferCopyConfiguredPolicySnapshot configuredBufferCopyPolicy,
        in QuicAdaptiveBackpressureConfiguredPolicySnapshot
            configuredAdaptiveBackpressurePolicy,
        IQuicAdaptiveRuntimeUnifiedEpochEvidenceSink sink)
        : this(
            in configuredStage1Policy,
            in configuredBufferCopyPolicy,
            in configuredAdaptiveBackpressurePolicy,
            QuicPacketFlushCadencePolicy.CreateConfiguredSnapshot(
                QuicPacketFlushCadenceObservationMode.Disabled,
                forcedValue: null),
            QuicReceiveDeliveryQuantumPolicy.CreateConfiguredSnapshot(
                QuicReceiveDeliveryQuantumObservationMode.Disabled,
                forcedValue: null),
            sink)
    {
    }

    internal QuicAdaptiveRuntimeUnifiedEpochEvidenceAccumulator(
        in QuicAdaptiveRuntimeStage1PolicySnapshot configuredStage1Policy,
        in QuicBufferCopyConfiguredPolicySnapshot configuredBufferCopyPolicy,
        in QuicAdaptiveBackpressureConfiguredPolicySnapshot
            configuredAdaptiveBackpressurePolicy,
        in QuicPacketFlushCadenceConfiguredPolicySnapshot
            configuredPacketFlushCadencePolicy,
        IQuicAdaptiveRuntimeUnifiedEpochEvidenceSink sink)
        : this(
            in configuredStage1Policy,
            in configuredBufferCopyPolicy,
            in configuredAdaptiveBackpressurePolicy,
            in configuredPacketFlushCadencePolicy,
            QuicReceiveDeliveryQuantumPolicy.CreateConfiguredSnapshot(
                QuicReceiveDeliveryQuantumObservationMode.Disabled,
                forcedValue: null),
            sink)
    {
    }

    internal QuicAdaptiveRuntimeUnifiedEpochEvidenceAccumulator(
        in QuicAdaptiveRuntimeStage1PolicySnapshot configuredStage1Policy,
        in QuicBufferCopyConfiguredPolicySnapshot configuredBufferCopyPolicy,
        in QuicAdaptiveBackpressureConfiguredPolicySnapshot
            configuredAdaptiveBackpressurePolicy,
        in QuicPacketFlushCadenceConfiguredPolicySnapshot
            configuredPacketFlushCadencePolicy,
        in QuicReceiveDeliveryQuantumConfiguredPolicySnapshot
            configuredReceiveDeliveryQuantumPolicy,
        IQuicAdaptiveRuntimeUnifiedEpochEvidenceSink sink)
    {
        ArgumentNullException.ThrowIfNull(sink);
        stage1 = new(in configuredStage1Policy);
        bufferCopy = new(in configuredBufferCopyPolicy);
        adaptiveBackpressure =
            new(in configuredAdaptiveBackpressurePolicy);
        packetFlushCadence =
            new(in configuredPacketFlushCadencePolicy);
        receiveDeliveryQuantum =
            new(in configuredReceiveDeliveryQuantumPolicy);
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
        in QuicAdaptiveBackpressureObservation observation)
    {
        lock (gate)
        {
            return adaptiveBackpressure.TryPublish(in observation);
        }
    }

    public bool TryPublish(
        in QuicPacketFlushCadenceObservation observation)
    {
        lock (gate)
        {
            return packetFlushCadence.TryPublish(in observation);
        }
    }

    public bool TryPublish(
        in QuicReceiveDeliveryQuantumObservation observation)
    {
        lock (gate)
        {
            return receiveDeliveryQuantum.TryPublish(in observation);
        }
    }

    public bool TryPublish(
        in QuicConnectionShardPlacementDecision decision)
    {
        lock (gate)
        {
            if (!string.Equals(
                    decision.AxisId,
                    QuicConnectionShardPlacementPolicy.AxisId,
                    StringComparison.Ordinal))
            {
                return false;
            }

            if (hasConnectionShardPlacementDecision)
            {
                return connectionShardPlacementDecision.Equals(decision);
            }

            connectionShardPlacementDecision = decision;
            hasConnectionShardPlacementDecision = true;
            return true;
        }
    }

    public bool TryPublish(
        in QuicApplicationDatagramBatchTransportConfiguredPolicySnapshot
            snapshot)
    {
        lock (gate)
        {
            if (hasApplicationDatagramBatchTransportConfiguredSnapshot
                && !applicationDatagramBatchTransportConfiguredSnapshot
                    .Equals(snapshot))
            {
                return false;
            }

            applicationDatagramBatchTransportConfiguredSnapshot = snapshot;
            hasApplicationDatagramBatchTransportConfiguredSnapshot = true;
            return true;
        }
    }

    public bool TryPublish(
        in QuicApplicationDatagramBatchTransportCapability capability)
    {
        lock (gate)
        {
            if (capability.CapabilityEpoch == 0)
            {
                return false;
            }

            applicationDatagramBatchTransportCapability = capability;
            hasApplicationDatagramBatchTransportCapability = true;
            applicationDatagramBatchTransportCapabilityEventCount =
                SaturatingIncrement(
                    applicationDatagramBatchTransportCapabilityEventCount);
            return true;
        }
    }

    public bool TryPublish(
        in QuicApplicationDatagramBatchTransportDecision decision)
    {
        lock (gate)
        {
            if (!string.Equals(
                    decision.AxisId,
                    QuicApplicationDatagramBatchTransportPolicy.AxisId,
                    StringComparison.Ordinal)
                || decision.Capability.CapabilityEpoch == 0)
            {
                return false;
            }

            applicationDatagramBatchTransportLastDecision = decision;
            hasApplicationDatagramBatchTransportDecision = true;
            applicationDatagramBatchTransportDecisionEventCount =
                SaturatingIncrement(
                    applicationDatagramBatchTransportDecisionEventCount);
            if (decision.BuildSegmentedBatch)
            {
                applicationDatagramBatchTransportSegmentedDecisionCount =
                    SaturatingIncrement(
                        applicationDatagramBatchTransportSegmentedDecisionCount);
            }
            else
            {
                applicationDatagramBatchTransportOrdinaryDecisionCount =
                    SaturatingIncrement(
                        applicationDatagramBatchTransportOrdinaryDecisionCount);
            }

            return true;
        }
    }

    public bool TryPublish(
        in QuicApplicationDatagramBatchTransportOutcome outcome)
    {
        lock (gate)
        {
            if (outcome.CapabilityEpoch == 0
                || outcome.SocketCallCount == 0
                || outcome.DatagramCount == 0
                || outcome.AcceptedBytes > outcome.SubmittedBytes)
            {
                return false;
            }

            applicationDatagramBatchTransportSocketCallCount =
                SaturatingAdd(
                    applicationDatagramBatchTransportSocketCallCount,
                    outcome.SocketCallCount);
            if (outcome.Kind
                == QuicApplicationDatagramBatchTransportOutcomeKind
                    .SegmentedBatch)
            {
                applicationDatagramBatchTransportSegmentedSocketCallCount =
                    SaturatingAdd(
                        applicationDatagramBatchTransportSegmentedSocketCallCount,
                        outcome.SocketCallCount);
            }
            else
            {
                applicationDatagramBatchTransportOrdinarySocketCallCount =
                    SaturatingAdd(
                        applicationDatagramBatchTransportOrdinarySocketCallCount,
                        outcome.SocketCallCount);
            }

            applicationDatagramBatchTransportDatagramCount =
                SaturatingAdd(
                    applicationDatagramBatchTransportDatagramCount,
                    outcome.DatagramCount);
            applicationDatagramBatchTransportSegmentCount =
                SaturatingAdd(
                    applicationDatagramBatchTransportSegmentCount,
                    outcome.SegmentCount);
            applicationDatagramBatchTransportSubmittedBytes =
                SaturatingAdd(
                    applicationDatagramBatchTransportSubmittedBytes,
                    outcome.SubmittedBytes);
            applicationDatagramBatchTransportAcceptedBytes =
                SaturatingAdd(
                    applicationDatagramBatchTransportAcceptedBytes,
                    outcome.AcceptedBytes);
            if (!outcome.Succeeded)
            {
                applicationDatagramBatchTransportFailedSocketCallCount =
                    SaturatingAdd(
                        applicationDatagramBatchTransportFailedSocketCallCount,
                        outcome.SocketCallCount);
            }

            if (outcome.PartialSend)
            {
                applicationDatagramBatchTransportPartialSendCount =
                    SaturatingIncrement(
                        applicationDatagramBatchTransportPartialSendCount);
            }

            if (outcome.LifecycleGuard)
            {
                applicationDatagramBatchTransportLifecycleGuardCount =
                    SaturatingIncrement(
                        applicationDatagramBatchTransportLifecycleGuardCount);
            }

            return true;
        }
    }

    public bool TryPublish(
        in QuicCongestionPacingProfileDecision decision)
    {
        lock (gate)
        {
            if (!string.Equals(
                    decision.AxisId,
                    QuicCongestionPacingProfilePolicy.AxisId,
                    StringComparison.Ordinal))
            {
                return false;
            }

            if (hasCongestionPacingProfileDecision)
            {
                return congestionPacingProfileDecision.Equals(decision);
            }

            congestionPacingProfileDecision = decision;
            hasCongestionPacingProfileDecision = true;
            return true;
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
            QuicAdaptiveBackpressureEpochSummary
                adaptiveBackpressureEvidence =
                    adaptiveBackpressure.CaptureAndReset();
            QuicPacketFlushCadenceEpochSummary packetFlushCadenceEvidence =
                packetFlushCadence.CaptureAndReset();
            QuicReceiveDeliveryQuantumEpochSummary receiveDeliveryEvidence =
                receiveDeliveryQuantum.CaptureAndReset();
            QuicConnectionShardPlacementEpochSummary placementEvidence =
                CaptureConnectionShardPlacement();
            QuicApplicationDatagramBatchTransportEpochSummary
                datagramBatchTransportEvidence =
                    CaptureApplicationDatagramBatchTransport();
            QuicCongestionPacingProfileEpochSummary congestionProfileEvidence =
                CaptureCongestionPacingProfile();
            QuicAdaptiveRuntimeUnifiedEpochEvidence unified = new(
                observation,
                snapshot,
                boundary,
                stage1Evidence,
                actorServiceEvidence,
                bufferCopyEvidence,
                adaptiveBackpressureEvidence,
                packetFlushCadenceEvidence,
                receiveDeliveryEvidence,
                placementEvidence,
                datagramBatchTransportEvidence,
                congestionProfileEvidence);

            lastEpochSequence = epochSequence;
            return sink.TryPublish(in unified);
        }
    }

    private QuicConnectionShardPlacementEpochSummary
        CaptureConnectionShardPlacement()
    {
        if (hasConnectionShardPlacementDecision)
        {
            return new(
                connectionShardPlacementDecision,
                HasDecision: true,
                EventCount: 1);
        }

        QuicConnectionShardPlacementDecision missing =
            QuicConnectionShardPlacementPolicy.Evaluate(
                QuicConnectionShardPlacementObservationMode.Disabled,
                forcedValue: null,
                connectionHandleValue: 0,
                shardCount: 0,
                legacyShardActiveConnections: 0,
                alternateShardActiveConnections: 0,
                lifecycleGuard: false,
                QuicConnectionShardPlacementValidity.MissingRequiredInput);
        return new(missing, HasDecision: false, EventCount: 0);
    }

    private QuicApplicationDatagramBatchTransportEpochSummary
        CaptureApplicationDatagramBatchTransport()
    {
        QuicApplicationDatagramBatchTransportEpochSummary summary = new(
            applicationDatagramBatchTransportConfiguredSnapshot,
            applicationDatagramBatchTransportCapability,
            applicationDatagramBatchTransportLastDecision,
            hasApplicationDatagramBatchTransportConfiguredSnapshot,
            hasApplicationDatagramBatchTransportCapability,
            hasApplicationDatagramBatchTransportDecision,
            applicationDatagramBatchTransportCapabilityEventCount,
            applicationDatagramBatchTransportDecisionEventCount,
            applicationDatagramBatchTransportSegmentedDecisionCount,
            applicationDatagramBatchTransportOrdinaryDecisionCount,
            applicationDatagramBatchTransportSocketCallCount,
            applicationDatagramBatchTransportOrdinarySocketCallCount,
            applicationDatagramBatchTransportSegmentedSocketCallCount,
            applicationDatagramBatchTransportDatagramCount,
            applicationDatagramBatchTransportSegmentCount,
            applicationDatagramBatchTransportSubmittedBytes,
            applicationDatagramBatchTransportAcceptedBytes,
            applicationDatagramBatchTransportFailedSocketCallCount,
            applicationDatagramBatchTransportPartialSendCount,
            applicationDatagramBatchTransportLifecycleGuardCount);
        applicationDatagramBatchTransportCapabilityEventCount = 0;
        applicationDatagramBatchTransportDecisionEventCount = 0;
        applicationDatagramBatchTransportSegmentedDecisionCount = 0;
        applicationDatagramBatchTransportOrdinaryDecisionCount = 0;
        applicationDatagramBatchTransportSocketCallCount = 0;
        applicationDatagramBatchTransportOrdinarySocketCallCount = 0;
        applicationDatagramBatchTransportSegmentedSocketCallCount = 0;
        applicationDatagramBatchTransportDatagramCount = 0;
        applicationDatagramBatchTransportSegmentCount = 0;
        applicationDatagramBatchTransportSubmittedBytes = 0;
        applicationDatagramBatchTransportAcceptedBytes = 0;
        applicationDatagramBatchTransportFailedSocketCallCount = 0;
        applicationDatagramBatchTransportPartialSendCount = 0;
        applicationDatagramBatchTransportLifecycleGuardCount = 0;
        return summary;
    }

    private QuicCongestionPacingProfileEpochSummary
        CaptureCongestionPacingProfile()
    {
        if (hasCongestionPacingProfileDecision)
        {
            return new(
                congestionPacingProfileDecision,
                HasDecision: true,
                EventCount: 1);
        }

        QuicCongestionPacingProfileDecision missing =
            QuicCongestionPacingProfilePolicy.Evaluate(
                QuicCongestionPacingProfileObservationMode.Disabled,
                forcedValue: null,
                connectionStartSequence: 0,
                captureTicks: 0,
                validity:
                    QuicCongestionPacingProfileValidity
                        .MissingRequiredInput);
        return new(missing, HasDecision: false, EventCount: 0);
    }

    private static ulong SaturatingIncrement(ulong value) =>
        value == ulong.MaxValue ? ulong.MaxValue : value + 1;

    private static ulong SaturatingAdd(ulong left, ulong right) =>
        ulong.MaxValue - left < right ? ulong.MaxValue : left + right;

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
