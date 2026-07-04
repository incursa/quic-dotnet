// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S9-4-P5-S2-R01")]
public sealed class RFC9000_S9_4_P5_S2_R01
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ValidatingANewPathArmsASeparatePathValidationTimerThatCancelsOnSuccess()
    {
        QuicConnectionPathIdentity activePath = new("203.0.113.10", RemotePort: 443);
        QuicConnectionPathIdentity candidatePath = new("203.0.113.11", RemotePort: 443);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithConfirmedHandshakeAndActivePath(activePath);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        QuicConnectionTransitionResult firstResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                candidatePath,
                datagram),
            nowTicks: 20);

        QuicS8P2PathValidationTestSupport.AssertSinglePathChallengeDatagram(
            firstResult,
            candidatePath,
            runtime: runtime);
        Assert.True(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.PathValidation).HasValue);
        Assert.Null(runtime.SendRuntime.LossDetectionDeadlineMicros);

        long validationDeadlineTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.PathValidation)!.Value;
        QuicConnectionTransitionResult validationResult = runtime.Transition(
            new QuicConnectionPathValidationSucceededEvent(
                ObservedAtTicks: validationDeadlineTicks - 1,
                candidatePath),
            nowTicks: validationDeadlineTicks - 1);

        Assert.Contains(validationResult.Effects, effect =>
            effect is QuicConnectionCancelTimerEffect cancel
            && cancel.TimerKind == QuicConnectionTimerKind.PathValidation);
        Assert.Null(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.PathValidation));
    }
}
