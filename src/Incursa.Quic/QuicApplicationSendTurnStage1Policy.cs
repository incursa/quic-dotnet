// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

internal enum QuicApplicationSendTurnStage1Reason : ushort
{
    LegacyCurrent = 0,
    Forced = 1,
    ObserveOnly = 2,
    ShadowLegacyCurrent = 3,
    MissingSignal = 4,
    StaleSignal = 5,
    ArithmeticSaturated = 6,
    Contradictory = 7,
    OutOfDomain = 8,
    RecoveryGuard = 9,
    ResourceGuard = 10,
    TerminalGuard = 11,
    DisposalGuard = 12,
}

internal static class QuicApplicationSendTurnStage1Policy
{
    internal static QuicAdaptiveRuntimeStage1AxisDecision Evaluate(
        in QuicApplicationSendTurnObservation observation,
        QuicApplicationSendTurnObservationMode observationMode,
        bool hasForcedValue,
        QuicApplicationSendTurnPolicyMode forcedValue,
        bool hasShadowRecommendation,
        QuicApplicationSendTurnPolicyMode shadowRecommendation)
    {
        if (observation.TurnSequence == 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(observation),
                "Application-send turn observations require a nonzero turn sequence.");
        }

        if (observationMode is < QuicApplicationSendTurnObservationMode.Disabled
            or > QuicApplicationSendTurnObservationMode.Shadow)
        {
            throw new ArgumentOutOfRangeException(nameof(observationMode));
        }

        if (hasForcedValue)
        {
            ValidateMode(forcedValue);
        }

        if (hasShadowRecommendation)
        {
            ValidateMode(shadowRecommendation);
        }

        QuicAdaptiveRuntimeStage1Validity validity = GetValidity(in observation);
        QuicApplicationSendTurnStage1Reason reason =
            GetReason(in observation, validity);
        QuicAdaptiveRuntimeStage1PolicyValue forcedStage1Value =
            ToStage1Value(forcedValue);
        QuicAdaptiveRuntimeStage1PolicyValue shadowStage1Value =
            ToStage1Value(shadowRecommendation);
        QuicAdaptiveRuntimeStage1PolicyValue selectedValue;
        QuicAdaptiveRuntimeStage1PolicyValue appliedValue;
        QuicAdaptiveRuntimeStage1SelectionSource selectionSource;
        if (hasForcedValue)
        {
            selectedValue = forcedStage1Value;
            appliedValue = forcedStage1Value;
            selectionSource = QuicAdaptiveRuntimeStage1SelectionSource.Forced;
            reason = QuicApplicationSendTurnStage1Reason.Forced;
        }
        else if (hasShadowRecommendation)
        {
            selectedValue = shadowStage1Value;
            appliedValue = QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent;
            selectionSource = QuicAdaptiveRuntimeStage1SelectionSource.ShadowRule;
            if (validity == QuicAdaptiveRuntimeStage1Validity.None
                && shadowRecommendation
                    == QuicApplicationSendTurnPolicyMode.LegacyCurrent)
            {
                reason = QuicApplicationSendTurnStage1Reason.ShadowLegacyCurrent;
            }
        }
        else
        {
            selectedValue = QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent;
            appliedValue = QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent;
            selectionSource = QuicAdaptiveRuntimeStage1SelectionSource.LegacySelector;
            reason = observationMode == QuicApplicationSendTurnObservationMode.ObserveOnly
                ? QuicApplicationSendTurnStage1Reason.ObserveOnly
                : QuicApplicationSendTurnStage1Reason.LegacyCurrent;
        }

        bool terminal =
            (observation.LifecycleFlags
                & (QuicAdaptiveRuntimeLifecycle.Terminal
                    | QuicAdaptiveRuntimeLifecycle.Disposed)) != 0;
        QuicAdaptiveRuntimeStage1FallbackState fallbackState;
        if (terminal)
        {
            fallbackState = QuicAdaptiveRuntimeStage1FallbackState.Terminal;
        }
        else
        {
            fallbackState = validity == QuicAdaptiveRuntimeStage1Validity.None
                ? QuicAdaptiveRuntimeStage1FallbackState.NotRequired
                : QuicAdaptiveRuntimeStage1FallbackState.Applied;
        }
        return new QuicAdaptiveRuntimeStage1AxisDecision(
            QuicAdaptiveRuntimeStage1Axis.ApplicationSendTurnPlanning,
            observation.ObservationContractVersion,
            observation.PolicyRuleVersion,
            QuicApplicationSendTurnPolicySnapshot.CurrentSnapshotContractVersion,
            QuicApplicationSendTurnPolicySnapshot.CurrentReasonVersion,
            QuicApplicationSendTurnPolicySnapshot.CurrentProvenanceVersion,
            validity,
            hasForcedValue,
            forcedStage1Value,
            hasShadowRecommendation,
            shadowStage1Value,
            selectedValue,
            appliedValue,
            selectionSource,
            (ushort)reason,
            QuicAdaptiveRuntimeStage1SafetyOverrideReason.None,
            QuicAdaptiveRuntimeStage1DecisionBoundary.ActorTurn,
            QuicAdaptiveRuntimeStage1LatchLifetime.ActorTurn,
            terminal
                ? QuicAdaptiveRuntimeStage1LatchState.Terminal
                : QuicAdaptiveRuntimeStage1LatchState.Completed,
            fallbackState,
            observation.TurnSequence,
            observation.TurnSequence);
    }

    internal static void ValidateMode(QuicApplicationSendTurnPolicyMode mode)
    {
        if (mode is < QuicApplicationSendTurnPolicyMode.LegacyCurrent
            or > QuicApplicationSendTurnPolicyMode.Conservative)
        {
            throw new ArgumentOutOfRangeException(nameof(mode));
        }
    }

    private static QuicAdaptiveRuntimeStage1PolicyValue ToStage1Value(
        QuicApplicationSendTurnPolicyMode mode)
        => mode switch
        {
            QuicApplicationSendTurnPolicyMode.LegacyCurrent =>
                QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent,
            QuicApplicationSendTurnPolicyMode.Conservative =>
                QuicAdaptiveRuntimeStage1PolicyValue.Conservative,
            _ => throw new ArgumentOutOfRangeException(nameof(mode)),
        };

    private static QuicAdaptiveRuntimeStage1Validity GetValidity(
        in QuicApplicationSendTurnObservation observation)
    {
        QuicAdaptiveRuntimeStage1Validity validity =
            QuicAdaptiveRuntimeStage1Validity.None;
        if (observation.MissingSignalMask != QuicApplicationSendTurnSignalMask.None)
        {
            validity |= QuicAdaptiveRuntimeStage1Validity.Missing;
        }

        if (observation.StaleSignalMask != QuicApplicationSendTurnSignalMask.None)
        {
            validity |= QuicAdaptiveRuntimeStage1Validity.Stale;
        }

        if ((observation.Conditions
            & QuicApplicationSendTurnObservationCondition.ArithmeticSaturated) != 0)
        {
            validity |= QuicAdaptiveRuntimeStage1Validity.Saturated;
        }

        if ((observation.Conditions
            & QuicApplicationSendTurnObservationCondition.Contradictory) != 0)
        {
            validity |= QuicAdaptiveRuntimeStage1Validity.Contradictory;
        }

        if ((observation.Conditions
            & QuicApplicationSendTurnObservationCondition.OutOfDomain) != 0)
        {
            validity |= QuicAdaptiveRuntimeStage1Validity.OutOfDomain;
        }

        return validity;
    }

    private static QuicApplicationSendTurnStage1Reason GetReason(
        in QuicApplicationSendTurnObservation observation,
        QuicAdaptiveRuntimeStage1Validity validity)
    {
        if ((observation.LifecycleFlags & QuicAdaptiveRuntimeLifecycle.Disposed) != 0)
        {
            return QuicApplicationSendTurnStage1Reason.DisposalGuard;
        }

        if ((observation.LifecycleFlags & QuicAdaptiveRuntimeLifecycle.Terminal) != 0)
        {
            return QuicApplicationSendTurnStage1Reason.TerminalGuard;
        }

        if ((observation.Conditions
            & QuicApplicationSendTurnObservationCondition.RecoveryUnstable) != 0)
        {
            return QuicApplicationSendTurnStage1Reason.RecoveryGuard;
        }

        if ((observation.Conditions
            & QuicApplicationSendTurnObservationCondition.ResourceConstrained) != 0)
        {
            return QuicApplicationSendTurnStage1Reason.ResourceGuard;
        }

        if ((validity & QuicAdaptiveRuntimeStage1Validity.Missing) != 0)
        {
            return QuicApplicationSendTurnStage1Reason.MissingSignal;
        }

        if ((validity & QuicAdaptiveRuntimeStage1Validity.Stale) != 0)
        {
            return QuicApplicationSendTurnStage1Reason.StaleSignal;
        }

        if ((validity & QuicAdaptiveRuntimeStage1Validity.Saturated) != 0)
        {
            return QuicApplicationSendTurnStage1Reason.ArithmeticSaturated;
        }

        if ((validity & QuicAdaptiveRuntimeStage1Validity.Contradictory) != 0)
        {
            return QuicApplicationSendTurnStage1Reason.Contradictory;
        }

        return (validity & QuicAdaptiveRuntimeStage1Validity.OutOfDomain) != 0
            ? QuicApplicationSendTurnStage1Reason.OutOfDomain
            : QuicApplicationSendTurnStage1Reason.LegacyCurrent;
    }
}
