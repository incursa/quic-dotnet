// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

internal enum QuicBufferCopyObservationMode : byte
{
    Disabled = 0,
    ObserveOnly = 1,
}

internal enum QuicBufferCopyPath : byte
{
    ApplicationWriteRequest = 0,
    OversizedRawQueue = 1,
    FormattedStreamPayload = 2,
    CombinedApplicationSend = 3,
    SentPacketPlaintextRetention = 4,
    RetransmissionClone = 5,
    ReceiveSegment = 6,
}

internal enum QuicBufferCopyOperation : byte
{
    Copy = 0,
    ReuseAndCopy = 1,
    Format = 2,
    Combine = 3,
    Retain = 4,
    Clone = 5,
}

internal enum QuicBufferCopyDecisionBoundary : byte
{
    StreamWriteRetry = 0,
    LogicalWriteAdmission = 1,
    PacketPlan = 2,
    SentPacketRetention = 3,
    RetransmissionClone = 4,
    ReceiveSegmentInsertion = 5,
}

internal enum QuicBufferCopyPolicyValue : byte
{
    LegacyCurrent = 0,
}

internal enum QuicBufferCopySelectionSource : byte
{
    LegacyCurrent = 0,
}

internal enum QuicBufferCopyReasonCode : byte
{
    LegacyCopy = 0,
    ExistingCapacityReused = 1,
}

internal enum QuicBufferCopySafetyOverride : byte
{
    None = 0,
}

internal enum QuicBufferCopyLatchLifetime : byte
{
    BufferLifetime = 0,
}

internal enum QuicBufferReleaseReason : byte
{
    Delivered = 0,
    Reset = 1,
}

[Flags]
internal enum QuicBufferReleaseValidity : byte
{
    None = 0,
    CapacityMismatch = 1 << 0,
    ArithmeticSaturated = 1 << 1,
    Contradictory = 1 << 2,
    OutOfDomain = 1 << 3,
}

[Flags]
internal enum QuicBufferCopyValidity : ushort
{
    None = 0,
    MissingTerminalReleaseCorrelation = 1 << 0,
    MissingRetainedAge = 1 << 1,
    MissingPoolOutstanding = 1 << 2,
    ArithmeticSaturated = 1 << 3,
    Contradictory = 1 << 4,
    OutOfDomain = 1 << 5,
}

internal readonly record struct QuicBufferCopyObservation(
    ulong OperationSequence,
    QuicBufferCopyPath Path,
    QuicBufferCopyOperation Operation,
    QuicBufferCopyDecisionBoundary DecisionBoundary,
    long? JoinOperationSequence,
    ulong LogicalBytes,
    ulong CopiedBytes,
    uint SourceSegmentCount,
    uint DestinationSegmentCount,
    ulong RequestedCapacityBytes,
    ulong RetainedCapacityBytes,
    QuicBufferCopyPolicyValue? ForcedValue,
    QuicBufferCopyPolicyValue? ShadowRecommendation,
    QuicBufferCopyPolicyValue SelectedValue,
    QuicBufferCopyPolicyValue AppliedValue,
    QuicBufferCopySelectionSource SelectionSource,
    QuicBufferCopyReasonCode ReasonCode,
    QuicBufferCopySafetyOverride SafetyOverride,
    QuicBufferCopyLatchLifetime LatchLifetime,
    bool FallbackApplied,
    QuicConnectionPhase PhaseAfter,
    bool DisposalStarted,
    QuicBufferCopyValidity Validity)
{
    internal const string AxisId = "buffer_copy_coalescing";
    internal const string CurrentObservationContractVersion =
        "quic-buffer-copy-observation-v2";
    internal const string CurrentRuleVersion =
        "quic-buffer-copy-observe-only-rule-v1";
    internal const string CurrentSnapshotVersion =
        "quic-buffer-copy-snapshot-v2";
    internal const string CurrentReasonVersion =
        "quic-buffer-copy-reason-v1";
    internal const string CurrentProvenanceVersion =
        "quic-buffer-copy-provenance-v2";

    public string PolicyAxisId => AxisId;

    public string ObservationContractVersion =>
        CurrentObservationContractVersion;

    public string RuleVersion => CurrentRuleVersion;

    public string SnapshotVersion => CurrentSnapshotVersion;

    public string ReasonVersion => CurrentReasonVersion;

    public string ProvenanceVersion => CurrentProvenanceVersion;
}

internal readonly record struct QuicBufferCopyLifetimeToken(
    ulong OperationSequence,
    QuicBufferCopyPath Path,
    long ConstructionTicks,
    ulong RetainedCapacityBytes)
{
    internal const string CurrentTokenContractVersion =
        "quic-buffer-copy-lifetime-token-v1";

    public string TokenContractVersion =>
        CurrentTokenContractVersion;

    public bool IsEmpty => OperationSequence == 0;
}

internal readonly record struct QuicBufferReleaseObservation(
    ulong ReleaseSequence,
    ulong OperationSequence,
    QuicBufferCopyPath Path,
    QuicBufferReleaseReason Reason,
    ulong ReleasedCapacityBytes,
    ulong LifetimeMicros,
    QuicConnectionPhase PhaseAfter,
    bool DisposalStarted,
    QuicBufferReleaseValidity Validity)
{
    internal const string CurrentObservationContractVersion =
        "quic-buffer-release-observation-v1";
    internal const string CurrentReasonVersion =
        "quic-buffer-release-reason-v1";
    internal const string CurrentProvenanceVersion =
        "quic-buffer-release-provenance-v1";

    public string ObservationContractVersion =>
        CurrentObservationContractVersion;

    public string TokenContractVersion =>
        QuicBufferCopyLifetimeToken.CurrentTokenContractVersion;

    public string ReasonVersion => CurrentReasonVersion;

    public string ProvenanceVersion => CurrentProvenanceVersion;
}

internal interface IQuicBufferCopyEvidenceSink
{
    bool TryPublish(in QuicBufferCopyObservation observation);
}

internal interface IQuicBufferReleaseEvidenceSink
{
    bool TryPublish(in QuicBufferReleaseObservation observation);
}

internal interface IQuicBufferCopyOperationObserver
{
    QuicBufferCopyLifetimeToken ObserveBufferCopy(
        QuicBufferCopyPath path,
        QuicBufferCopyOperation operation,
        QuicBufferCopyDecisionBoundary decisionBoundary,
        long? joinOperationSequence,
        int logicalBytes,
        int copiedBytes,
        int sourceSegmentCount,
        int requestedCapacityBytes,
        int retainedCapacityBytes,
        bool trackTerminalRelease);

    void ObserveBufferRelease(
        in QuicBufferCopyLifetimeToken token,
        QuicBufferReleaseReason reason,
        int releasedCapacityBytes);
}
