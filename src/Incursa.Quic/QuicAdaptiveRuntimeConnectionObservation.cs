// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

[Flags]
internal enum QuicAdaptiveRuntimeSignalMask : uint
{
    None = 0,
    HasIssuedApplicationData = 1U << 0,
    LiveObserverStreams = 1U << 1,
    Lifecycle = 1U << 2,
    QueueDelayEwma = 1U << 3,
}

[Flags]
internal enum QuicAdaptiveRuntimeLifecycle : byte
{
    None = 0,
    Establishing = 1 << 0,
    Active = 1 << 1,
    Closing = 1 << 2,
    Draining = 1 << 3,
    Discarded = 1 << 4,
    Terminal = 1 << 5,
    Disposed = 1 << 6,
}

internal readonly record struct QuicAdaptiveRuntimeConnectionObservation(
    ulong ConnectionEpochSequence,
    long EpochStartTicks,
    long EpochEndTicks,
    ulong ActiveDurationMicros,
    string ObservationContractVersion,
    string PolicyRuleVersion,
    ulong? AdvisorAgeMicros,
    QuicAdaptiveRuntimeSignalMask MissingSignalMask,
    QuicAdaptiveRuntimeSignalMask StaleSignalMask,
    QuicAdaptiveRuntimeLifecycle LifecycleFlags,
    bool HasIssuedApplicationData,
    ushort OpenStreams,
    ushort LiveObserverStreams,
    uint QueuedApplicationWrites,
    uint QueueDelayEwmaMicros)
{
    internal const string CurrentObservationContractVersion = "adaptive-runtime-connection-observation-v1";
    internal const string CurrentPolicyRuleVersion = "receive-credit-legacy-v1";
}

internal enum QuicAdaptiveRuntimePostServiceBoundarySource : byte
{
    HostedShard = 0,
    IndependentConsumer = 1,
}

[Flags]
internal enum QuicAdaptiveRuntimePostServiceBoundaryValidity : byte
{
    None = 0,
    ActorObservationUnavailable = 1 << 0,
    ResourceReleaseIncomplete = 1 << 1,
    FaultedService = 1 << 2,
}

internal readonly record struct QuicAdaptiveRuntimePostServiceBoundary(
    ulong ConnectionEpochSequence,
    long EpochEndTicks,
    QuicAdaptiveRuntimePostServiceBoundarySource Source,
    QuicActorServiceDisposition Disposition,
    ulong? ActorServiceSequence,
    bool ActorObservationPublished,
    bool ResourceReleaseCompleted,
    QuicAdaptiveRuntimePostServiceBoundaryValidity Validity)
{
    internal const string CurrentBoundaryContractVersion =
        "adaptive-runtime-post-service-boundary-v1";

    public string BoundaryContractVersion =>
        CurrentBoundaryContractVersion;
}

internal interface IQuicAdaptiveRuntimeShadowEpochSink
{
    bool TryPublish(
        in QuicAdaptiveRuntimeConnectionObservation observation,
        in QuicReceiveCreditPolicySnapshot snapshot,
        in QuicAdaptiveRuntimePostServiceBoundary boundary);
}
