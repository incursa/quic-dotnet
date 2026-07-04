// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Diagnostics;

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S9-4-P5-S4-R01")]
public sealed class RFC9000_S9_4_P5_S4_R01
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void InitialPathValidationTimerUsesTheCurrentProbeTimeoutBudget()
    {
        QuicConnectionPathIdentity activePath = new("203.0.113.30", RemotePort: 443);
        QuicConnectionPathIdentity candidatePath = new("203.0.113.31", RemotePort: 443);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithConfirmedHandshakeAndActivePath(activePath);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];
        ulong expectedProbeTimeoutMicros = runtime.CurrentProbeTimeoutMicros;

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                candidatePath,
                datagram),
            nowTicks: 20).StateChanged);

        Assert.True(runtime.CandidatePaths.TryGetValue(candidatePath, out QuicConnectionCandidatePathRecord candidate));
        Assert.True(candidate.Validation.ChallengeSentAtTicks.HasValue);
        Assert.True(candidate.Validation.ValidationDeadlineTicks.HasValue);
        Assert.Equal(1UL, candidate.Validation.ChallengeSendCount);

        long expectedIntervalTicks = MicrosecondsToTicks(expectedProbeTimeoutMicros);
        long observedIntervalTicks = candidate.Validation.ValidationDeadlineTicks.Value - candidate.Validation.ChallengeSentAtTicks.Value;

        Assert.Equal(expectedIntervalTicks, observedIntervalTicks);
        Assert.Equal(candidate.Validation.ValidationDeadlineTicks, runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.PathValidation));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void InitialPathValidationTimerDoesNotUseAnImmediateOrUnsetDeadline()
    {
        QuicConnectionPathIdentity activePath = new("203.0.113.32", RemotePort: 443);
        QuicConnectionPathIdentity candidatePath = new("203.0.113.33", RemotePort: 443);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithConfirmedHandshakeAndActivePath(activePath);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                candidatePath,
                datagram),
            nowTicks: 20).StateChanged);

        Assert.True(runtime.CandidatePaths.TryGetValue(candidatePath, out QuicConnectionCandidatePathRecord candidate));
        Assert.True(candidate.Validation.ChallengeSentAtTicks.HasValue);
        Assert.True(candidate.Validation.ValidationDeadlineTicks.HasValue);
        Assert.True(candidate.Validation.ValidationDeadlineTicks.Value > candidate.Validation.ChallengeSentAtTicks.Value);
        Assert.NotEqual(candidate.Validation.ChallengeSentAtTicks, candidate.Validation.ValidationDeadlineTicks);
        Assert.Equal(candidate.Validation.ValidationDeadlineTicks, runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.PathValidation));
    }

    private static long MicrosecondsToTicks(ulong micros)
    {
        if (micros == 0)
        {
            return 0;
        }

        ulong frequency = (ulong)Stopwatch.Frequency;
        ulong wholeTicks = micros > ulong.MaxValue / frequency
            ? ulong.MaxValue
            : micros * frequency;

        ulong roundedUp = wholeTicks == ulong.MaxValue
            ? wholeTicks
            : wholeTicks + 999_999UL;

        ulong ticks = roundedUp / 1_000_000UL;
        return ticks >= long.MaxValue ? long.MaxValue : (long)ticks;
    }
}
