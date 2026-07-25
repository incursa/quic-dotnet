// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

internal enum QuicBufferCopyObservationMode : byte
{
    Disabled = 0,
    ObserveOnly = 1,
    Shadow = 2,
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
    OutboundPacketProtection = 7,
}

internal enum QuicBufferCopyOperation : byte
{
    Copy = 0,
    ReuseAndCopy = 1,
    Format = 2,
    Combine = 3,
    Retain = 4,
    Clone = 5,
    Protect = 6,
}

internal enum QuicBufferCopyDecisionBoundary : byte
{
    StreamWriteRetry = 0,
    LogicalWriteAdmission = 1,
    PacketPlan = 2,
    SentPacketRetention = 3,
    RetransmissionClone = 4,
    ReceiveSegmentInsertion = 5,
    PacketProtection = 6,
}

internal enum QuicBufferCopyPolicyValue : byte
{
    LegacyCurrent = 0,
    MemoryConservative = 1,
}

internal enum QuicBufferCopySelectionSource : byte
{
    LegacyCurrent = 0,
    Forced = 1,
    ShadowRule = 2,
    SafetyOverride = 3,
}

internal enum QuicBufferCopyReasonCode : byte
{
    LegacyCopy = 0,
    ExistingCapacityReused = 1,
    ObserveOnly = 2,
    Forced = 3,
    ShadowMemoryConservative = 4,
    MissingInput = 5,
    StaleInput = 6,
    ArithmeticSaturated = 7,
    Contradictory = 8,
    OutOfDomain = 9,
    InvalidInput = 10,
    LifecycleGuard = 11,
    NotApplicable = 12,
}

internal enum QuicBufferCopySafetyOverride : byte
{
    None = 0,
    InvalidObservation = 1,
    Lifecycle = 2,
}

internal enum QuicBufferCopyLatchLifetime : byte
{
    BufferLifetime = 0,
}

internal enum QuicBufferReleaseReason : byte
{
    Delivered = 0,
    Reset = 1,
    CopiedToNextOwner = 2,
    Completed = 3,
    Failed = 4,
    Canceled = 5,
    Terminal = 6,
    Disposed = 7,
    Replaced = 8,
    Recycled = 9,
}

[Flags]
internal enum QuicBufferReleaseValidity : byte
{
    None = 0,
    CapacityMismatch = 1 << 0,
    ArithmeticSaturated = 1 << 1,
    Contradictory = 1 << 2,
    OutOfDomain = 1 << 3,
    MissingToken = 1 << 4,
    Duplicate = 1 << 5,
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
    StaleRequiredInput = 1 << 6,
    InvalidInput = 1 << 7,
}

internal readonly record struct QuicBufferCopyConfiguredPolicySnapshot(
    QuicBufferCopyObservationMode Mode,
    bool HasForcedValue,
    QuicBufferCopyPolicyValue ForcedValue,
    bool HasShadowRecommendation,
    QuicBufferCopyPolicyValue ShadowRecommendation,
    QuicBufferCopyPolicyValue SelectedValue,
    QuicBufferCopyPolicyValue AppliedValue,
    QuicBufferCopySelectionSource SelectionSource,
    QuicBufferCopyReasonCode ReasonCode,
    QuicBufferCopySafetyOverride SafetyOverride,
    QuicBufferCopyLatchLifetime LatchLifetime,
    bool FallbackApplied)
{
    internal const string CurrentSnapshotVersion =
        "quic-buffer-copy-policy-snapshot-v1";

    public string SnapshotVersion => CurrentSnapshotVersion;
}

internal readonly record struct QuicBufferCopyPolicyDecision(
    QuicBufferCopyObservationMode Mode,
    bool HasForcedValue,
    QuicBufferCopyPolicyValue ForcedValue,
    bool HasShadowRecommendation,
    QuicBufferCopyPolicyValue ShadowRecommendation,
    QuicBufferCopyPolicyValue SelectedValue,
    QuicBufferCopyPolicyValue AppliedValue,
    QuicBufferCopySelectionSource SelectionSource,
    QuicBufferCopyReasonCode ReasonCode,
    QuicBufferCopySafetyOverride SafetyOverride,
    QuicBufferCopyLatchLifetime LatchLifetime,
    bool FallbackApplied,
    int LegalSourceSegmentCount,
    int AppliedSourceSegmentCount);

internal static class QuicBufferCopyPolicy
{
    internal const int MinimumCombinedSourceSegments = 2;
    internal const int MemoryConservativeMaximumSourceSegments =
        MinimumCombinedSourceSegments;
    internal const string CurrentRuleVersion =
        "quic-buffer-copy-memory-conservative-rule-v1";
    internal const string CurrentReasonVersion =
        "quic-buffer-copy-reason-v2";
    internal const string CurrentProvenanceVersion =
        "quic-buffer-copy-provenance-v4";

    internal static void ValidateValue(QuicBufferCopyPolicyValue value)
    {
        if (value is < QuicBufferCopyPolicyValue.LegacyCurrent
            or > QuicBufferCopyPolicyValue.MemoryConservative)
        {
            throw new ArgumentOutOfRangeException(nameof(value));
        }
    }

    internal static void ValidateObservationMode(
        QuicBufferCopyObservationMode mode)
    {
        if (mode is < QuicBufferCopyObservationMode.Disabled
            or > QuicBufferCopyObservationMode.Shadow)
        {
            throw new ArgumentOutOfRangeException(nameof(mode));
        }
    }

    internal static QuicBufferCopyConfiguredPolicySnapshot CreateConfiguredSnapshot(
        QuicBufferCopyObservationMode mode,
        QuicBufferCopyPolicyValue? forcedValue)
    {
        ValidateObservationMode(mode);
        if (forcedValue is { } forced)
        {
            ValidateValue(forced);
            bool hasShadowRecommendation =
                mode == QuicBufferCopyObservationMode.Shadow;
            return new(
                mode,
                HasForcedValue: true,
                forced,
                hasShadowRecommendation,
                ShadowRecommendation: hasShadowRecommendation
                    ? QuicBufferCopyPolicyValue.MemoryConservative
                    : QuicBufferCopyPolicyValue.LegacyCurrent,
                SelectedValue: forced,
                AppliedValue: forced,
                QuicBufferCopySelectionSource.Forced,
                QuicBufferCopyReasonCode.Forced,
                QuicBufferCopySafetyOverride.None,
                QuicBufferCopyLatchLifetime.BufferLifetime,
                FallbackApplied: false);
        }

        if (mode == QuicBufferCopyObservationMode.Shadow)
        {
            return new(
                mode,
                HasForcedValue: false,
                ForcedValue: QuicBufferCopyPolicyValue.LegacyCurrent,
                HasShadowRecommendation: true,
                ShadowRecommendation:
                    QuicBufferCopyPolicyValue.MemoryConservative,
                SelectedValue: QuicBufferCopyPolicyValue.MemoryConservative,
                AppliedValue: QuicBufferCopyPolicyValue.LegacyCurrent,
                QuicBufferCopySelectionSource.ShadowRule,
                QuicBufferCopyReasonCode.ShadowMemoryConservative,
                QuicBufferCopySafetyOverride.None,
                QuicBufferCopyLatchLifetime.BufferLifetime,
                FallbackApplied: false);
        }

        return new(
            mode,
            HasForcedValue: false,
            ForcedValue: QuicBufferCopyPolicyValue.LegacyCurrent,
            HasShadowRecommendation: false,
            ShadowRecommendation: QuicBufferCopyPolicyValue.LegacyCurrent,
            SelectedValue: QuicBufferCopyPolicyValue.LegacyCurrent,
            AppliedValue: QuicBufferCopyPolicyValue.LegacyCurrent,
            QuicBufferCopySelectionSource.LegacyCurrent,
            mode == QuicBufferCopyObservationMode.ObserveOnly
                ? QuicBufferCopyReasonCode.ObserveOnly
                : QuicBufferCopyReasonCode.LegacyCopy,
            QuicBufferCopySafetyOverride.None,
            QuicBufferCopyLatchLifetime.BufferLifetime,
            FallbackApplied: false);
    }

    internal static QuicBufferCopyPolicyDecision Evaluate(
        QuicBufferCopyObservationMode mode,
        QuicBufferCopyPolicyValue? forcedValue,
        int legalSourceSegmentCount,
        QuicBufferCopyValidity validity,
        bool lifecycleGuard)
    {
        QuicBufferCopyConfiguredPolicySnapshot configured =
            CreateConfiguredSnapshot(mode, forcedValue);
        bool invalidSourceSegmentCount =
            legalSourceSegmentCount < MinimumCombinedSourceSegments;
        QuicBufferCopySafetyOverride safetyOverride =
            invalidSourceSegmentCount
                ? QuicBufferCopySafetyOverride.InvalidObservation
                : GetSafetyOverride(validity, lifecycleGuard);
        bool fallbackApplied =
            safetyOverride != QuicBufferCopySafetyOverride.None;
        QuicBufferCopyPolicyValue appliedValue = fallbackApplied
            ? QuicBufferCopyPolicyValue.LegacyCurrent
            : configured.AppliedValue;
        QuicBufferCopySelectionSource selectionSource = fallbackApplied
            ? QuicBufferCopySelectionSource.SafetyOverride
            : configured.SelectionSource;
        QuicBufferCopyReasonCode reasonCode = configured.ReasonCode;
        if (invalidSourceSegmentCount)
        {
            reasonCode =
                GetInvalidSourceSegmentCountReason(legalSourceSegmentCount);
        }
        else if (fallbackApplied)
        {
            reasonCode = GetFallbackReason(validity, lifecycleGuard);
        }
        int appliedSourceSegmentCount = invalidSourceSegmentCount
            ? Math.Max(0, legalSourceSegmentCount)
            : SelectSourceSegmentCount(
                appliedValue,
                legalSourceSegmentCount);

        return new(
            mode,
            configured.HasForcedValue,
            configured.ForcedValue,
            configured.HasShadowRecommendation,
            configured.ShadowRecommendation,
            configured.SelectedValue,
            appliedValue,
            selectionSource,
            reasonCode,
            safetyOverride,
            configured.LatchLifetime,
            fallbackApplied,
            legalSourceSegmentCount,
            appliedSourceSegmentCount);
    }

    private static QuicBufferCopyReasonCode GetInvalidSourceSegmentCountReason(
        int legalSourceSegmentCount)
    {
        if (legalSourceSegmentCount == 0)
        {
            return QuicBufferCopyReasonCode.MissingInput;
        }

        return legalSourceSegmentCount < 0
            ? QuicBufferCopyReasonCode.OutOfDomain
            : QuicBufferCopyReasonCode.Contradictory;
    }

    internal static int SelectSourceSegmentCount(
        QuicBufferCopyPolicyValue value,
        int legalSourceSegmentCount)
    {
        ValidateValue(value);
        if (legalSourceSegmentCount < MinimumCombinedSourceSegments)
        {
            throw new ArgumentOutOfRangeException(
                nameof(legalSourceSegmentCount),
                "A combined-send buffer policy requires at least two legal source segments.");
        }

        return value == QuicBufferCopyPolicyValue.MemoryConservative
            ? Math.Min(
                MemoryConservativeMaximumSourceSegments,
                legalSourceSegmentCount)
            : legalSourceSegmentCount;
    }

    private static QuicBufferCopySafetyOverride GetSafetyOverride(
        QuicBufferCopyValidity validity,
        bool lifecycleGuard)
    {
        if (lifecycleGuard)
        {
            return QuicBufferCopySafetyOverride.Lifecycle;
        }

        const QuicBufferCopyValidity invalidMask =
            QuicBufferCopyValidity.ArithmeticSaturated
            | QuicBufferCopyValidity.Contradictory
            | QuicBufferCopyValidity.OutOfDomain
            | QuicBufferCopyValidity.StaleRequiredInput
            | QuicBufferCopyValidity.InvalidInput;
        return (validity & invalidMask) != 0
            ? QuicBufferCopySafetyOverride.InvalidObservation
            : QuicBufferCopySafetyOverride.None;
    }

    private static QuicBufferCopyReasonCode GetFallbackReason(
        QuicBufferCopyValidity validity,
        bool lifecycleGuard)
    {
        if (lifecycleGuard)
        {
            return QuicBufferCopyReasonCode.LifecycleGuard;
        }

        if ((validity & QuicBufferCopyValidity.StaleRequiredInput) != 0)
        {
            return QuicBufferCopyReasonCode.StaleInput;
        }

        if ((validity & QuicBufferCopyValidity.ArithmeticSaturated) != 0)
        {
            return QuicBufferCopyReasonCode.ArithmeticSaturated;
        }

        if ((validity & QuicBufferCopyValidity.Contradictory) != 0)
        {
            return QuicBufferCopyReasonCode.Contradictory;
        }

        if ((validity & QuicBufferCopyValidity.OutOfDomain) != 0)
        {
            return QuicBufferCopyReasonCode.OutOfDomain;
        }

        return QuicBufferCopyReasonCode.InvalidInput;
    }
}

internal readonly record struct QuicBufferCopyObservation(
    ulong OperationSequence,
    QuicBufferCopyObservationMode Mode,
    QuicBufferCopyPath Path,
    QuicBufferCopyOperation Operation,
    QuicBufferCopyDecisionBoundary DecisionBoundary,
    long? JoinOperationSequence,
    ulong LegalLogicalBytes,
    ulong LogicalBytes,
    ulong CopiedBytes,
    uint LegalSourceSegmentCount,
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
        "quic-buffer-copy-observation-v4";
    internal const string CurrentRuleVersion =
        QuicBufferCopyPolicy.CurrentRuleVersion;
    internal const string CurrentSnapshotVersion =
        QuicBufferCopyConfiguredPolicySnapshot.CurrentSnapshotVersion;
    internal const string CurrentReasonVersion =
        QuicBufferCopyPolicy.CurrentReasonVersion;
    internal const string CurrentProvenanceVersion =
        QuicBufferCopyPolicy.CurrentProvenanceVersion;

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
        "quic-buffer-release-observation-v7";
    internal const string CurrentReasonVersion =
        "quic-buffer-release-reason-v7";
    internal const string CurrentProvenanceVersion =
        "quic-buffer-release-provenance-v7";

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
