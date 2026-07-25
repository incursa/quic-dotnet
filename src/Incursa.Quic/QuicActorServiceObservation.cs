// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

internal enum QuicActorServiceObservationMode : byte
{
    Disabled = 0,
    ObserveOnly = 1,
}

internal enum QuicActorWorkKind : byte
{
    ConnectionEvent = 0,
    Timer = 1,
    PacketReceived = 2,
    StreamCapacityRelease = 3,
    FlowControlCreditUpdate = 4,
    StreamOpen = 5,
    StreamWrite = 6,
}

internal enum QuicActorWakeCompletion : byte
{
    ConsumerStart = 0,
    Synchronous = 1,
    Asynchronous = 2,
}

internal enum QuicActorWakeSource : byte
{
    ConsumerStart = 0,
    Inbox = 1,
    Deadline = 2,
}

internal enum QuicActorServiceDisposition : byte
{
    Completed = 0,
    SkippedDisposed = 1,
    SkippedIndependentConsumer = 2,
    Faulted = 3,
}

[Flags]
internal enum QuicActorServiceValidity : ushort
{
    None = 0,
    MissingQueueDelay = 1 << 0,
    MissingRunnableConnectionCount = 1 << 1,
    MissingOldestShardItemAge = 1 << 2,
    MissingDeadlineLateness = 1 << 3,
    UsefulWorkUnitsUndefined = 1 << 4,
    ArithmeticSaturated = 1 << 5,
    MissingInterServiceGap = 1 << 6,
    TimeDomainOutOfRange = 1 << 7,
    MissingServiceContenderCount = 1 << 8,
    ServiceContenderStateInvalid = 1 << 9,
    MissingAcceptedConnectionWorkItemsAfterCurrent = 1 << 10,
    IncompleteContinuationAssessment = 1 << 11,
    ContinuationAssessmentInvalid = 1 << 12,
}

internal readonly record struct QuicActorServiceObservation(
    ulong ServiceSequence,
    int ShardIndex,
    ulong WakeSequence,
    uint WakePosition,
    QuicActorWakeCompletion WakeCompletion,
    QuicActorWakeSource WakeSource,
    QuicActorWorkKind WorkKind,
    QuicActorServiceDisposition Disposition,
    ulong? QueueDelayMicros,
    ulong ServiceTimeMicros,
    ulong PendingWorkItemsAfterDequeue,
    uint EffectCount,
    uint ApplicationSendFollowOnCount,
    uint FlowControlFollowOnCount,
    uint StreamCapacityFollowOnCount,
    QuicConnectionPhase PhaseAfter,
    bool DisposalStarted,
    QuicActorServiceValidity Validity,
    ulong? InterServiceGapMicros = null,
    ulong? DeadlineLatenessMicros = null,
    ulong? ServiceContenderCountAtStart = null,
    ulong? AcceptedConnectionWorkItemsAfterCurrent = null,
    QuicActorContinuationAssessment ContinuationAssessment = default)
{
    internal const string CurrentObservationContractVersion =
        "quic-actor-service-observation-v5";
    internal const string CurrentProvenanceVersion =
        "quic-actor-service-provenance-v5";

    public string ObservationContractVersion =>
        CurrentObservationContractVersion;

    public string ProvenanceVersion => CurrentProvenanceVersion;
}

internal interface IQuicActorServiceEvidenceSink
{
    bool TryPublish(in QuicActorServiceObservation observation);
}
