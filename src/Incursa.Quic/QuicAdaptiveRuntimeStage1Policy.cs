// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

internal enum QuicAdaptiveRuntimeStage1Axis : byte
{
    ApplicationSendTurnPlanning = 0,
    ApplicationSendBatchFormation = 1,
    QueuedSendBurstBudget = 2,
    OversizedWriteAdmissionQuantum = 3,
}

internal enum QuicAdaptiveRuntimeStage1PolicyValue : byte
{
    LegacyCurrent = 0,
    Conservative = 1,
    SingleEligible = 2,
    SingleDatagram = 3,
    SingleFragment = 4,
    BoundedMultiFragment = 5,
}

[Flags]
internal enum QuicAdaptiveRuntimeStage1Validity : byte
{
    None = 0,
    Missing = 1 << 0,
    Stale = 1 << 1,
    Saturated = 1 << 2,
    Contradictory = 1 << 3,
    OutOfDomain = 1 << 4,
}

internal enum QuicAdaptiveRuntimeStage1SelectionSource : byte
{
    LegacySelector = 0,
    Forced = 1,
    ShadowRule = 2,
    Fallback = 3,
    SafetyOverride = 4,
}

internal enum QuicAdaptiveRuntimeStage1DecisionBoundary : byte
{
    ActorTurn = 0,
    PacketPlan = 1,
    LogicalWriteAdmission = 2,
}

internal enum QuicAdaptiveRuntimeStage1LatchLifetime : byte
{
    ActorTurn = 0,
    PacketPlan = 1,
    LogicalWrite = 2,
}

internal enum QuicAdaptiveRuntimeStage1LatchState : byte
{
    Unlatched = 0,
    Latched = 1,
    Completed = 2,
    Fallback = 3,
    Terminal = 4,
}

internal enum QuicAdaptiveRuntimeStage1FallbackState : byte
{
    NotRequired = 0,
    Eligible = 1,
    Applied = 2,
    Terminal = 3,
}

internal enum QuicAdaptiveRuntimeStage1SafetyOverrideReason : byte
{
    None = 0,
    MissingSignal = 1,
    StaleSignal = 2,
    Saturated = 3,
    Contradictory = 4,
    OutOfDomain = 5,
    Recovery = 6,
    Congestion = 7,
    Pacing = 8,
    FlowControl = 9,
    Resource = 10,
    Cancellation = 11,
    Disposal = 12,
    Terminal = 13,
}

internal readonly record struct QuicAdaptiveRuntimeStage1AxisDecision(
    QuicAdaptiveRuntimeStage1Axis Axis,
    string ObservationContractVersion,
    string RuleVersion,
    string SnapshotVersion,
    string ReasonVersion,
    string ProvenanceVersion,
    QuicAdaptiveRuntimeStage1Validity Validity,
    bool HasForcedValue,
    QuicAdaptiveRuntimeStage1PolicyValue ForcedValue,
    bool HasShadowRecommendation,
    QuicAdaptiveRuntimeStage1PolicyValue ShadowRecommendation,
    QuicAdaptiveRuntimeStage1PolicyValue SelectedValue,
    QuicAdaptiveRuntimeStage1PolicyValue AppliedValue,
    QuicAdaptiveRuntimeStage1SelectionSource SelectionSource,
    ushort ReasonCode,
    QuicAdaptiveRuntimeStage1SafetyOverrideReason SafetyOverrideReason,
    QuicAdaptiveRuntimeStage1DecisionBoundary DecisionBoundary,
    QuicAdaptiveRuntimeStage1LatchLifetime LatchLifetime,
    QuicAdaptiveRuntimeStage1LatchState LatchState,
    QuicAdaptiveRuntimeStage1FallbackState FallbackState,
    ulong DecisionSequence,
    ulong LatchSequence)
{
    internal bool SafetyOverrideApplied =>
        SafetyOverrideReason != QuicAdaptiveRuntimeStage1SafetyOverrideReason.None;
}

internal readonly record struct QuicAdaptiveRuntimeStage1PolicySnapshot
{
    internal const string CurrentSnapshotVersion =
        "adaptive-runtime-stage1-policy-snapshot-v1";

    internal QuicAdaptiveRuntimeStage1PolicySnapshot(
        QuicAdaptiveRuntimeStage1AxisDecision applicationSendTurnPlanning,
        QuicAdaptiveRuntimeStage1AxisDecision applicationSendBatchFormation,
        QuicAdaptiveRuntimeStage1AxisDecision queuedSendBurstBudget,
        QuicAdaptiveRuntimeStage1AxisDecision oversizedWriteAdmissionQuantum)
    {
        ValidateDecision(
            in applicationSendTurnPlanning,
            QuicAdaptiveRuntimeStage1Axis.ApplicationSendTurnPlanning);
        ValidateDecision(
            in applicationSendBatchFormation,
            QuicAdaptiveRuntimeStage1Axis.ApplicationSendBatchFormation);
        ValidateDecision(
            in queuedSendBurstBudget,
            QuicAdaptiveRuntimeStage1Axis.QueuedSendBurstBudget);
        ValidateDecision(
            in oversizedWriteAdmissionQuantum,
            QuicAdaptiveRuntimeStage1Axis.OversizedWriteAdmissionQuantum);

        Span<QuicAdaptiveRuntimeStage1AxisDecision> decisions =
        [
            applicationSendTurnPlanning,
            applicationSendBatchFormation,
            queuedSendBurstBudget,
            oversizedWriteAdmissionQuantum,
        ];

        int forcedCount = 0;
        foreach (ref readonly QuicAdaptiveRuntimeStage1AxisDecision decision in decisions)
        {
            if (decision.HasForcedValue)
            {
                forcedCount++;
                if (!decision.SafetyOverrideApplied
                    && decision.AppliedValue != decision.ForcedValue)
                {
                    throw new ArgumentException(
                        "A forced Stage 1 value must equal the applied value unless a safety override is recorded.");
                }
            }
            else if (decision.AppliedValue != QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent)
            {
                throw new ArgumentException(
                    "Every adjacent, unforced Stage 1 axis must apply legacy_current.");
            }

            if (decision.SafetyOverrideApplied
                != (decision.SelectionSource == QuicAdaptiveRuntimeStage1SelectionSource.SafetyOverride))
            {
                throw new ArgumentException(
                    "Stage 1 safety override state and selection source must agree.");
            }
        }

        if (forcedCount > 1)
        {
            throw new ArgumentException(
                "A Stage 1 counterfactual snapshot may force at most one policy axis.");
        }

        ApplicationSendTurnPlanning = applicationSendTurnPlanning;
        ApplicationSendBatchFormation = applicationSendBatchFormation;
        QueuedSendBurstBudget = queuedSendBurstBudget;
        OversizedWriteAdmissionQuantum = oversizedWriteAdmissionQuantum;
    }

    internal QuicAdaptiveRuntimeStage1AxisDecision ApplicationSendTurnPlanning { get; }

    internal QuicAdaptiveRuntimeStage1AxisDecision ApplicationSendBatchFormation { get; }

    internal QuicAdaptiveRuntimeStage1AxisDecision QueuedSendBurstBudget { get; }

    internal QuicAdaptiveRuntimeStage1AxisDecision OversizedWriteAdmissionQuantum { get; }

    private static void ValidateDecision(
        in QuicAdaptiveRuntimeStage1AxisDecision decision,
        QuicAdaptiveRuntimeStage1Axis expectedAxis)
    {
        if (decision.Axis != expectedAxis)
        {
            throw new ArgumentException(
                $"Expected Stage 1 axis '{expectedAxis}' but received '{decision.Axis}'.");
        }

        if (decision.DecisionSequence == 0
            || string.IsNullOrWhiteSpace(decision.ObservationContractVersion)
            || string.IsNullOrWhiteSpace(decision.RuleVersion)
            || string.IsNullOrWhiteSpace(decision.SnapshotVersion)
            || string.IsNullOrWhiteSpace(decision.ReasonVersion)
            || string.IsNullOrWhiteSpace(decision.ProvenanceVersion))
        {
            throw new ArgumentException(
                "Stage 1 decisions require nonzero sequence and complete version provenance.");
        }

        ValidatePolicyValue(expectedAxis, decision.SelectedValue);
        ValidatePolicyValue(expectedAxis, decision.AppliedValue);
        if (decision.HasForcedValue)
        {
            ValidatePolicyValue(expectedAxis, decision.ForcedValue);
        }

        if (decision.HasShadowRecommendation)
        {
            ValidatePolicyValue(expectedAxis, decision.ShadowRecommendation);
        }

        (QuicAdaptiveRuntimeStage1DecisionBoundary Boundary,
            QuicAdaptiveRuntimeStage1LatchLifetime Lifetime) expectedLatch = expectedAxis switch
        {
            QuicAdaptiveRuntimeStage1Axis.ApplicationSendTurnPlanning =>
                (QuicAdaptiveRuntimeStage1DecisionBoundary.ActorTurn,
                    QuicAdaptiveRuntimeStage1LatchLifetime.ActorTurn),
            QuicAdaptiveRuntimeStage1Axis.ApplicationSendBatchFormation =>
                (QuicAdaptiveRuntimeStage1DecisionBoundary.PacketPlan,
                    QuicAdaptiveRuntimeStage1LatchLifetime.PacketPlan),
            QuicAdaptiveRuntimeStage1Axis.QueuedSendBurstBudget =>
                (QuicAdaptiveRuntimeStage1DecisionBoundary.ActorTurn,
                    QuicAdaptiveRuntimeStage1LatchLifetime.ActorTurn),
            QuicAdaptiveRuntimeStage1Axis.OversizedWriteAdmissionQuantum =>
                (QuicAdaptiveRuntimeStage1DecisionBoundary.LogicalWriteAdmission,
                    QuicAdaptiveRuntimeStage1LatchLifetime.LogicalWrite),
            _ => throw new ArgumentOutOfRangeException(nameof(expectedAxis)),
        };

        if (decision.DecisionBoundary != expectedLatch.Boundary
            || decision.LatchLifetime != expectedLatch.Lifetime)
        {
            throw new ArgumentException(
                $"Stage 1 axis '{expectedAxis}' has an invalid decision boundary or latch lifetime.");
        }
    }

    private static void ValidatePolicyValue(
        QuicAdaptiveRuntimeStage1Axis axis,
        QuicAdaptiveRuntimeStage1PolicyValue value)
    {
        bool valid = axis switch
        {
            QuicAdaptiveRuntimeStage1Axis.ApplicationSendTurnPlanning =>
                value is QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent
                    or QuicAdaptiveRuntimeStage1PolicyValue.Conservative,
            QuicAdaptiveRuntimeStage1Axis.ApplicationSendBatchFormation =>
                value is QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent
                    or QuicAdaptiveRuntimeStage1PolicyValue.SingleEligible,
            QuicAdaptiveRuntimeStage1Axis.QueuedSendBurstBudget =>
                value is QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent
                    or QuicAdaptiveRuntimeStage1PolicyValue.SingleDatagram,
            QuicAdaptiveRuntimeStage1Axis.OversizedWriteAdmissionQuantum =>
                value is QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent
                    or QuicAdaptiveRuntimeStage1PolicyValue.SingleFragment
                    or QuicAdaptiveRuntimeStage1PolicyValue.BoundedMultiFragment,
            _ => false,
        };

        if (!valid)
        {
            throw new ArgumentException(
                $"Policy value '{value}' is not valid for Stage 1 axis '{axis}'.");
        }
    }
}
