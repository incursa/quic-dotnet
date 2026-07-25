// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

internal enum QuicApplicationDatagramBatchTransportObservationMode : byte
{
    Disabled = 0,
    ObserveOnly = 1,
    Shadow = 2,
}

internal enum QuicApplicationDatagramBatchTransportPolicyValue : byte
{
    LegacyCurrent = 0,
    SegmentedBatch = 1,
    OrdinaryDatagrams = 2,
}

internal enum QuicApplicationDatagramBatchTransportSelectionSource : byte
{
    LegacyCurrent = 0,
    Forced = 1,
    ShadowRule = 2,
    SafetyOverride = 3,
}

internal enum QuicApplicationDatagramBatchTransportReasonCode : byte
{
    LegacySparseBatch = 0,
    LegacyPressureTurn = 1,
    LegacyPressurePromotion = 2,
    LegacyPromotedOrdinary = 3,
    ObserveOnly = 4,
    ShadowOrdinaryDatagrams = 5,
    ForcedSegmentedBatch = 6,
    ForcedOrdinaryDatagrams = 7,
    ForcedLegacyCurrent = 8,
    CapabilityUnavailable = 9,
    MissingInput = 10,
    StaleInput = 11,
    ArithmeticSaturated = 12,
    Contradictory = 13,
    OutOfDomain = 14,
    InvalidInput = 15,
    LifecycleGuard = 16,
}

internal enum QuicApplicationDatagramBatchTransportSafetyOverride : byte
{
    None = 0,
    CapabilityUnavailable = 1,
    InvalidObservation = 2,
    Lifecycle = 3,
}

internal enum QuicApplicationDatagramBatchTransportDecisionBoundary : byte
{
    ApplicationSendTurn = 0,
}

internal enum QuicApplicationDatagramBatchTransportLatchLifetime : byte
{
    ConnectionLifetimeOrCapabilityEpoch = 0,
}

internal enum QuicApplicationDatagramBatchTransportCapabilityStatus : byte
{
    Missing = 0,
    WindowsUdpSendMessageSize = 1,
    UnsupportedPlatform = 2,
    UnsupportedAddressFamily = 3,
    ProbeFailed = 4,
    DisabledByCustomSender = 5,
}

internal enum QuicApplicationDatagramBatchTransportOutcomeKind : byte
{
    OrdinaryDatagram = 0,
    SegmentedBatch = 1,
}

[Flags]
internal enum QuicApplicationDatagramBatchTransportValidity : byte
{
    None = 0,
    MissingRequiredInput = 1 << 0,
    StaleRequiredInput = 1 << 1,
    ArithmeticSaturated = 1 << 2,
    Contradictory = 1 << 3,
    OutOfDomain = 1 << 4,
    InvalidInput = 1 << 5,
}

internal readonly record struct
    QuicApplicationDatagramBatchTransportCapability(
        ulong CapabilityEpoch,
        QuicApplicationDatagramBatchTransportCapabilityStatus Status)
{
    internal const string CurrentCapabilityVersion =
        "quic-application-datagram-batch-transport-capability-v1";

    public bool IsSupported =>
        Status
            == QuicApplicationDatagramBatchTransportCapabilityStatus
                .WindowsUdpSendMessageSize;

    public string CapabilityVersion => CurrentCapabilityVersion;
}

internal readonly record struct
    QuicApplicationDatagramBatchTransportConfiguredPolicySnapshot(
        QuicApplicationDatagramBatchTransportObservationMode Mode,
        bool HasForcedValue,
        QuicApplicationDatagramBatchTransportPolicyValue ForcedValue,
        bool HasShadowRecommendation,
        QuicApplicationDatagramBatchTransportPolicyValue
            ShadowRecommendation,
        QuicApplicationDatagramBatchTransportPolicyValue SelectedValue,
        QuicApplicationDatagramBatchTransportPolicyValue AppliedValue,
        QuicApplicationDatagramBatchTransportSelectionSource
            SelectionSource,
        QuicApplicationDatagramBatchTransportReasonCode ReasonCode,
        QuicApplicationDatagramBatchTransportSafetyOverride SafetyOverride,
        QuicApplicationDatagramBatchTransportDecisionBoundary
            DecisionBoundary,
        QuicApplicationDatagramBatchTransportLatchLifetime LatchLifetime,
        bool FallbackApplied)
{
    internal const string CurrentSnapshotVersion =
        "quic-application-datagram-batch-transport-policy-snapshot-v1";

    public string SnapshotVersion => CurrentSnapshotVersion;
}

internal readonly record struct
    QuicApplicationDatagramBatchTransportDecision(
        QuicApplicationDatagramBatchTransportObservationMode Mode,
        bool HasForcedValue,
        QuicApplicationDatagramBatchTransportPolicyValue ForcedValue,
        bool HasShadowRecommendation,
        QuicApplicationDatagramBatchTransportPolicyValue
            ShadowRecommendation,
        QuicApplicationDatagramBatchTransportPolicyValue SelectedValue,
        QuicApplicationDatagramBatchTransportPolicyValue AppliedValue,
        QuicApplicationDatagramBatchTransportSelectionSource
            SelectionSource,
        QuicApplicationDatagramBatchTransportReasonCode ReasonCode,
        QuicApplicationDatagramBatchTransportSafetyOverride SafetyOverride,
        QuicApplicationDatagramBatchTransportDecisionBoundary
            DecisionBoundary,
        QuicApplicationDatagramBatchTransportLatchLifetime LatchLifetime,
        bool FallbackApplied,
        QuicApplicationDatagramBatchTransportCapability Capability,
        uint DistinctQueuedStreamCount,
        uint ConsecutivePressureTurns,
        bool LegacyPromoted,
        bool BuildSegmentedBatch,
        QuicApplicationDatagramBatchTransportValidity Validity)
{
    internal const string CurrentObservationContractVersion =
        "quic-application-datagram-batch-transport-observation-v1";

    public string AxisId => QuicApplicationDatagramBatchTransportPolicy.AxisId;

    public string ObservationContractVersion =>
        CurrentObservationContractVersion;

    public string SnapshotVersion =>
        QuicApplicationDatagramBatchTransportConfiguredPolicySnapshot
            .CurrentSnapshotVersion;

    public string RuleVersion =>
        QuicApplicationDatagramBatchTransportPolicy.CurrentRuleVersion;

    public string ReasonVersion =>
        QuicApplicationDatagramBatchTransportPolicy.CurrentReasonVersion;

    public string ProvenanceVersion =>
        QuicApplicationDatagramBatchTransportPolicy
            .CurrentProvenanceVersion;
}

internal readonly record struct
    QuicApplicationDatagramBatchTransportOutcome(
        QuicApplicationDatagramBatchTransportOutcomeKind Kind,
        ulong CapabilityEpoch,
        uint SocketCallCount,
        uint DatagramCount,
        uint SegmentCount,
        ulong SubmittedBytes,
        ulong AcceptedBytes,
        bool Succeeded,
        bool PartialSend,
        bool LifecycleGuard);

internal interface IQuicApplicationDatagramBatchTransportEvidenceSink
{
    bool TryPublish(
        in QuicApplicationDatagramBatchTransportConfiguredPolicySnapshot
            snapshot);

    bool TryPublish(
        in QuicApplicationDatagramBatchTransportCapability capability);

    bool TryPublish(
        in QuicApplicationDatagramBatchTransportDecision decision);

    bool TryPublish(
        in QuicApplicationDatagramBatchTransportOutcome outcome);
}

/// <summary>
/// Decides whether one connection may construct a contiguous application-datagram batch.
/// </summary>
/// <remarks>
/// Implementations observe only bounded distinct-stream pressure. They do not own writes, packets, or
/// transport state and cannot change the runtime-computed send budget.
/// </remarks>
internal interface IQuicApplicationDatagramBatchPolicy
{
    bool IsPromoted { get; }

    QuicApplicationDatagramBatchTransportConfiguredPolicySnapshot
        ConfiguredSnapshot { get; }

    bool ShouldBuildBatch(int queuedStreamCount);

    void ObserveCapability(
        in QuicApplicationDatagramBatchTransportCapability capability);

    void ConfigureEvidenceSink(
        IQuicApplicationDatagramBatchTransportEvidenceSink sink);

    void RecordOutcome(
        in QuicApplicationDatagramBatchTransportOutcome outcome);
}

/// <summary>
/// Starts on the low-pressure segmented path and promotes one way after sustained queue pressure.
/// </summary>
internal sealed class QuicAdaptiveApplicationDatagramBatchPolicy : IQuicApplicationDatagramBatchPolicy
{
    internal const int DefaultRequiredConsecutivePressureTurns = 2;

    private readonly object gate = new();
    private readonly QuicApplicationDatagramBatchTransportObservationMode
        observationMode;
    private readonly QuicApplicationDatagramBatchTransportPolicyValue?
        forcedValue;
    private readonly int pressureStreamCount;
    private readonly int requiredConsecutivePressureTurns;
    private readonly bool legacyPressurePromotionEnabled;
    private QuicApplicationDatagramBatchTransportCapability capability;
    private int consecutivePressureTurns;
    private int promoted;
    private IQuicApplicationDatagramBatchTransportEvidenceSink?
        evidenceSink;
    private bool evidenceSinkConfigured;
    private QuicApplicationDatagramBatchTransportDecision lastDecision;
    private bool hasLastDecision;

    internal QuicAdaptiveApplicationDatagramBatchPolicy(
        int pressureStreamCount,
        int requiredConsecutivePressureTurns)
        : this(
            QuicApplicationDatagramBatchTransportObservationMode.Disabled,
            forcedValue: null,
            pressureStreamCount,
            requiredConsecutivePressureTurns)
    {
        capability = new(
            CapabilityEpoch: 1,
            QuicApplicationDatagramBatchTransportCapabilityStatus
                .WindowsUdpSendMessageSize);
    }

    internal QuicAdaptiveApplicationDatagramBatchPolicy(
        QuicApplicationDatagramBatchTransportObservationMode
            observationMode =
                QuicApplicationDatagramBatchTransportObservationMode
                    .Disabled,
        QuicApplicationDatagramBatchTransportPolicyValue? forcedValue = null,
        int pressureStreamCount = QuicConnectionRuntime.HostedApplicationDatagramBatchCapacity,
        int requiredConsecutivePressureTurns = DefaultRequiredConsecutivePressureTurns,
        bool legacyPressurePromotionEnabled = true)
    {
        QuicApplicationDatagramBatchTransportPolicy.ValidateObservationMode(
            observationMode);
        if (forcedValue is { } forced)
        {
            QuicApplicationDatagramBatchTransportPolicy.ValidateValue(forced);
        }

        if (pressureStreamCount <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(pressureStreamCount));
        }

        if (requiredConsecutivePressureTurns <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(requiredConsecutivePressureTurns));
        }

        this.observationMode = observationMode;
        this.forcedValue = forcedValue;
        this.pressureStreamCount = pressureStreamCount;
        this.requiredConsecutivePressureTurns = requiredConsecutivePressureTurns;
        this.legacyPressurePromotionEnabled =
            legacyPressurePromotionEnabled;
        capability = new(
            CapabilityEpoch: 0,
            QuicApplicationDatagramBatchTransportCapabilityStatus.Missing);
    }

    public bool IsPromoted => Volatile.Read(ref promoted) != 0;

    public QuicApplicationDatagramBatchTransportConfiguredPolicySnapshot
        ConfiguredSnapshot =>
            QuicApplicationDatagramBatchTransportPolicy
                .CreateConfiguredSnapshot(observationMode, forcedValue);

    public bool ShouldBuildBatch(int queuedStreamCount)
    {
        QuicApplicationDatagramBatchTransportDecision decision;
        IQuicApplicationDatagramBatchTransportEvidenceSink? sink;
        lock (gate)
        {
            decision = EvaluateLocked(
                queuedStreamCount,
                QuicApplicationDatagramBatchTransportValidity.None,
                lifecycleGuard: false);
            lastDecision = decision;
            hasLastDecision = true;
            sink = evidenceSink;
        }

        TryPublish(sink, in decision);
        return decision.BuildSegmentedBatch;
    }

    internal QuicApplicationDatagramBatchTransportDecision EvaluateForTest(
        int queuedStreamCount,
        QuicApplicationDatagramBatchTransportValidity validity,
        bool lifecycleGuard)
    {
        lock (gate)
        {
            return EvaluateLocked(
                queuedStreamCount,
                validity,
                lifecycleGuard);
        }
    }

    public void ObserveCapability(
        in QuicApplicationDatagramBatchTransportCapability capability)
    {
        IQuicApplicationDatagramBatchTransportEvidenceSink? sink;
        lock (gate)
        {
            if (capability.CapabilityEpoch == 0)
            {
                throw new ArgumentOutOfRangeException(nameof(capability));
            }

            this.capability = capability;
            sink = evidenceSink;
        }

        TryPublish(sink, in capability);
    }

    public void ConfigureEvidenceSink(
        IQuicApplicationDatagramBatchTransportEvidenceSink sink)
    {
        ArgumentNullException.ThrowIfNull(sink);
        QuicApplicationDatagramBatchTransportCapability currentCapability;
        QuicApplicationDatagramBatchTransportConfiguredPolicySnapshot
            configuredSnapshot;
        QuicApplicationDatagramBatchTransportDecision currentDecision;
        bool publishDecision;
        lock (gate)
        {
            if (evidenceSinkConfigured)
            {
                throw new InvalidOperationException(
                    "The application datagram batch transport evidence sink has already been configured.");
            }

            evidenceSinkConfigured = true;
            evidenceSink = sink;
            configuredSnapshot = ConfiguredSnapshot;
            currentCapability = capability;
            currentDecision = lastDecision;
            publishDecision = hasLastDecision;
        }

        TryPublish(sink, in configuredSnapshot);
        TryPublish(sink, in currentCapability);
        if (publishDecision)
        {
            TryPublish(sink, in currentDecision);
        }
    }

    public void RecordOutcome(
        in QuicApplicationDatagramBatchTransportOutcome outcome)
    {
        IQuicApplicationDatagramBatchTransportEvidenceSink? sink;
        lock (gate)
        {
            sink = evidenceSink;
        }

        TryPublish(sink, in outcome);
    }

    private QuicApplicationDatagramBatchTransportDecision EvaluateLocked(
        int queuedStreamCount,
        QuicApplicationDatagramBatchTransportValidity validity,
        bool lifecycleGuard)
    {
        if (queuedStreamCount < 0)
        {
            validity |=
                QuicApplicationDatagramBatchTransportValidity.OutOfDomain;
        }

        QuicApplicationDatagramBatchTransportConfiguredPolicySnapshot
            configured =
                QuicApplicationDatagramBatchTransportPolicy
                    .CreateConfiguredSnapshot(observationMode, forcedValue);
        bool legacySelected =
            configured.AppliedValue
                == QuicApplicationDatagramBatchTransportPolicyValue
                    .LegacyCurrent;
        bool capabilityAvailable = capability.IsSupported;
        QuicApplicationDatagramBatchTransportPolicyValue appliedValue;
        QuicApplicationDatagramBatchTransportSelectionSource
            selectionSource = configured.SelectionSource;
        QuicApplicationDatagramBatchTransportReasonCode reasonCode;
        QuicApplicationDatagramBatchTransportSafetyOverride
            safetyOverride =
                QuicApplicationDatagramBatchTransportSafetyOverride.None;
        bool fallbackApplied = false;
        bool buildSegmentedBatch = false;

        if (lifecycleGuard)
        {
            appliedValue =
                QuicApplicationDatagramBatchTransportPolicyValue
                    .OrdinaryDatagrams;
            selectionSource =
                QuicApplicationDatagramBatchTransportSelectionSource
                    .SafetyOverride;
            reasonCode =
                QuicApplicationDatagramBatchTransportReasonCode
                    .LifecycleGuard;
            safetyOverride =
                QuicApplicationDatagramBatchTransportSafetyOverride
                    .Lifecycle;
            fallbackApplied = true;
        }
        else if (validity
            != QuicApplicationDatagramBatchTransportValidity.None)
        {
            appliedValue =
                QuicApplicationDatagramBatchTransportPolicyValue
                    .OrdinaryDatagrams;
            selectionSource =
                QuicApplicationDatagramBatchTransportSelectionSource
                    .SafetyOverride;
            reasonCode = GetValidityReason(validity);
            safetyOverride =
                QuicApplicationDatagramBatchTransportSafetyOverride
                    .InvalidObservation;
            fallbackApplied = true;
        }
        else if (!capabilityAvailable
            && configured.AppliedValue
                is not QuicApplicationDatagramBatchTransportPolicyValue
                    .OrdinaryDatagrams)
        {
            appliedValue =
                QuicApplicationDatagramBatchTransportPolicyValue
                    .OrdinaryDatagrams;
            selectionSource =
                QuicApplicationDatagramBatchTransportSelectionSource
                    .SafetyOverride;
            reasonCode =
                QuicApplicationDatagramBatchTransportReasonCode
                    .CapabilityUnavailable;
            safetyOverride =
                QuicApplicationDatagramBatchTransportSafetyOverride
                    .CapabilityUnavailable;
            fallbackApplied = true;
        }
        else if (!legacySelected)
        {
            appliedValue = configured.AppliedValue;
            buildSegmentedBatch =
                appliedValue
                    == QuicApplicationDatagramBatchTransportPolicyValue
                        .SegmentedBatch;
            reasonCode = buildSegmentedBatch
                ? QuicApplicationDatagramBatchTransportReasonCode
                    .ForcedSegmentedBatch
                : QuicApplicationDatagramBatchTransportReasonCode
                    .ForcedOrdinaryDatagrams;
        }
        else if (IsPromoted)
        {
            appliedValue =
                QuicApplicationDatagramBatchTransportPolicyValue
                    .OrdinaryDatagrams;
            reasonCode =
                QuicApplicationDatagramBatchTransportReasonCode
                    .LegacyPromotedOrdinary;
        }
        else if (!legacyPressurePromotionEnabled
            || queuedStreamCount < pressureStreamCount)
        {
            consecutivePressureTurns = 0;
            appliedValue =
                QuicApplicationDatagramBatchTransportPolicyValue
                    .SegmentedBatch;
            buildSegmentedBatch = true;
            reasonCode =
                QuicApplicationDatagramBatchTransportReasonCode
                    .LegacySparseBatch;
        }
        else
        {
            consecutivePressureTurns++;
            if (consecutivePressureTurns
                < requiredConsecutivePressureTurns)
            {
                appliedValue =
                    QuicApplicationDatagramBatchTransportPolicyValue
                        .SegmentedBatch;
                buildSegmentedBatch = true;
                reasonCode =
                    QuicApplicationDatagramBatchTransportReasonCode
                        .LegacyPressureTurn;
            }
            else
            {
                Volatile.Write(ref promoted, 1);
                appliedValue =
                    QuicApplicationDatagramBatchTransportPolicyValue
                        .OrdinaryDatagrams;
                reasonCode =
                    QuicApplicationDatagramBatchTransportReasonCode
                        .LegacyPressurePromotion;
            }
        }

        return new(
            observationMode,
            configured.HasForcedValue,
            configured.ForcedValue,
            configured.HasShadowRecommendation,
            configured.ShadowRecommendation,
            configured.SelectedValue,
            appliedValue,
            selectionSource,
            reasonCode,
            safetyOverride,
            configured.DecisionBoundary,
            configured.LatchLifetime,
            fallbackApplied,
            capability,
            queuedStreamCount < 0 ? 0U : (uint)queuedStreamCount,
            (uint)Math.Max(0, consecutivePressureTurns),
            IsPromoted,
            buildSegmentedBatch,
            validity);
    }

    private static QuicApplicationDatagramBatchTransportReasonCode
        GetValidityReason(
            QuicApplicationDatagramBatchTransportValidity validity)
    {
        if ((validity
            & QuicApplicationDatagramBatchTransportValidity
                .MissingRequiredInput) != 0)
        {
            return QuicApplicationDatagramBatchTransportReasonCode
                .MissingInput;
        }

        if ((validity
            & QuicApplicationDatagramBatchTransportValidity
                .StaleRequiredInput) != 0)
        {
            return QuicApplicationDatagramBatchTransportReasonCode
                .StaleInput;
        }

        if ((validity
            & QuicApplicationDatagramBatchTransportValidity
                .ArithmeticSaturated) != 0)
        {
            return QuicApplicationDatagramBatchTransportReasonCode
                .ArithmeticSaturated;
        }

        if ((validity
            & QuicApplicationDatagramBatchTransportValidity
                .Contradictory) != 0)
        {
            return QuicApplicationDatagramBatchTransportReasonCode
                .Contradictory;
        }

        if ((validity
            & QuicApplicationDatagramBatchTransportValidity
                .OutOfDomain) != 0)
        {
            return QuicApplicationDatagramBatchTransportReasonCode
                .OutOfDomain;
        }

        return QuicApplicationDatagramBatchTransportReasonCode
            .InvalidInput;
    }

    private static void TryPublish(
        IQuicApplicationDatagramBatchTransportEvidenceSink? sink,
        in QuicApplicationDatagramBatchTransportConfiguredPolicySnapshot
            snapshot)
    {
        if (sink is null)
        {
            return;
        }

        try
        {
            _ = sink.TryPublish(in snapshot);
        }
        catch (Exception)
        {
            // Evidence remains behavior-neutral.
        }
    }

    private static void TryPublish(
        IQuicApplicationDatagramBatchTransportEvidenceSink? sink,
        in QuicApplicationDatagramBatchTransportCapability capability)
    {
        if (sink is null)
        {
            return;
        }

        try
        {
            _ = sink.TryPublish(in capability);
        }
        catch (Exception)
        {
            // Evidence remains behavior-neutral.
        }
    }

    private static void TryPublish(
        IQuicApplicationDatagramBatchTransportEvidenceSink? sink,
        in QuicApplicationDatagramBatchTransportDecision decision)
    {
        if (sink is null)
        {
            return;
        }

        try
        {
            _ = sink.TryPublish(in decision);
        }
        catch (Exception)
        {
            // Evidence remains behavior-neutral.
        }
    }

    private static void TryPublish(
        IQuicApplicationDatagramBatchTransportEvidenceSink? sink,
        in QuicApplicationDatagramBatchTransportOutcome outcome)
    {
        if (sink is null)
        {
            return;
        }

        try
        {
            _ = sink.TryPublish(in outcome);
        }
        catch (Exception)
        {
            // Evidence remains behavior-neutral.
        }
    }
}

internal static class QuicApplicationDatagramBatchTransportPolicy
{
    internal const string AxisId =
        "application_datagram_batch_transport";
    internal const string CurrentRuleVersion =
        "quic-application-datagram-batch-transport-rule-v1";
    internal const string CurrentReasonVersion =
        "quic-application-datagram-batch-transport-reason-v1";
    internal const string CurrentProvenanceVersion =
        "quic-application-datagram-batch-transport-provenance-v1";

    internal static void ValidateValue(
        QuicApplicationDatagramBatchTransportPolicyValue value)
    {
        if (value
            is < QuicApplicationDatagramBatchTransportPolicyValue
                .LegacyCurrent
            or > QuicApplicationDatagramBatchTransportPolicyValue
                .OrdinaryDatagrams)
        {
            throw new ArgumentOutOfRangeException(nameof(value));
        }
    }

    internal static void ValidateObservationMode(
        QuicApplicationDatagramBatchTransportObservationMode mode)
    {
        if (mode
            is < QuicApplicationDatagramBatchTransportObservationMode
                .Disabled
            or > QuicApplicationDatagramBatchTransportObservationMode
                .Shadow)
        {
            throw new ArgumentOutOfRangeException(nameof(mode));
        }
    }

    internal static
        QuicApplicationDatagramBatchTransportConfiguredPolicySnapshot
        CreateConfiguredSnapshot(
            QuicApplicationDatagramBatchTransportObservationMode mode,
            QuicApplicationDatagramBatchTransportPolicyValue? forcedValue)
    {
        ValidateObservationMode(mode);
        if (forcedValue is { } forced)
        {
            ValidateValue(forced);
            return new(
                mode,
                HasForcedValue: true,
                forced,
                HasShadowRecommendation:
                    mode
                        == QuicApplicationDatagramBatchTransportObservationMode
                            .Shadow,
                ShadowRecommendation:
                    QuicApplicationDatagramBatchTransportPolicyValue
                        .OrdinaryDatagrams,
                SelectedValue: forced,
                AppliedValue: forced,
                QuicApplicationDatagramBatchTransportSelectionSource.Forced,
                forced switch
                {
                    QuicApplicationDatagramBatchTransportPolicyValue
                        .SegmentedBatch =>
                        QuicApplicationDatagramBatchTransportReasonCode
                            .ForcedSegmentedBatch,
                    QuicApplicationDatagramBatchTransportPolicyValue
                        .OrdinaryDatagrams =>
                        QuicApplicationDatagramBatchTransportReasonCode
                            .ForcedOrdinaryDatagrams,
                    _ =>
                        QuicApplicationDatagramBatchTransportReasonCode
                            .ForcedLegacyCurrent,
                },
                QuicApplicationDatagramBatchTransportSafetyOverride.None,
                QuicApplicationDatagramBatchTransportDecisionBoundary
                    .ApplicationSendTurn,
                QuicApplicationDatagramBatchTransportLatchLifetime
                    .ConnectionLifetimeOrCapabilityEpoch,
                FallbackApplied: false);
        }

        bool shadow =
            mode
                == QuicApplicationDatagramBatchTransportObservationMode
                    .Shadow;
        QuicApplicationDatagramBatchTransportReasonCode reasonCode =
            mode
                == QuicApplicationDatagramBatchTransportObservationMode
                    .ObserveOnly
                ? QuicApplicationDatagramBatchTransportReasonCode
                    .ObserveOnly
                : QuicApplicationDatagramBatchTransportReasonCode
                    .LegacySparseBatch;
        if (shadow)
        {
            reasonCode =
                QuicApplicationDatagramBatchTransportReasonCode
                    .ShadowOrdinaryDatagrams;
        }

        return new(
            mode,
            HasForcedValue: false,
            ForcedValue:
                QuicApplicationDatagramBatchTransportPolicyValue
                    .LegacyCurrent,
            HasShadowRecommendation: shadow,
            ShadowRecommendation: shadow
                ? QuicApplicationDatagramBatchTransportPolicyValue
                    .OrdinaryDatagrams
                : QuicApplicationDatagramBatchTransportPolicyValue
                    .LegacyCurrent,
            SelectedValue: shadow
                ? QuicApplicationDatagramBatchTransportPolicyValue
                    .OrdinaryDatagrams
                : QuicApplicationDatagramBatchTransportPolicyValue
                    .LegacyCurrent,
            AppliedValue:
                QuicApplicationDatagramBatchTransportPolicyValue
                    .LegacyCurrent,
            shadow
                ? QuicApplicationDatagramBatchTransportSelectionSource
                    .ShadowRule
                : QuicApplicationDatagramBatchTransportSelectionSource
                    .LegacyCurrent,
            reasonCode,
            QuicApplicationDatagramBatchTransportSafetyOverride.None,
            QuicApplicationDatagramBatchTransportDecisionBoundary
                .ApplicationSendTurn,
            QuicApplicationDatagramBatchTransportLatchLifetime
                .ConnectionLifetimeOrCapabilityEpoch,
            FallbackApplied: false);
    }
}
