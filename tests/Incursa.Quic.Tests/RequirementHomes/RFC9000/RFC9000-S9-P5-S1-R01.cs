// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S9-P5-S1-R01")]
public sealed class REQ_QUIC_RFC9000_0464
{
    [Fact]
    [Requirement("RFC9000-S9-P5-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PathValidationFailureDiscardsStateOnlyWhenNoValidatedPathRemains()
    {
        for (int variation = 0; variation < 4; variation++)
        {
            if (variation % 2 == 0)
            {
                QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntime();
                QuicConnectionPathIdentity failedPath = new($"203.0.113.{240 + variation}", RemotePort: 443);

                Assert.False(runtime.HasValidatedPath);
                Assert.Null(runtime.ActivePath);

                QuicConnectionTransitionResult result = runtime.Transition(
                    new QuicConnectionPathValidationFailedEvent(
                        ObservedAtTicks: 20 + variation,
                        failedPath,
                        IsAbandoned: true),
                    nowTicks: 20 + variation);

                Assert.True(result.StateChanged);
                Assert.Equal(QuicConnectionPhase.Discarded, runtime.Phase);
                Assert.Equal(QuicConnectionSendingMode.None, runtime.SendingMode);
                Assert.False(runtime.CanSendOrdinaryPackets);
                Assert.True(runtime.TerminalState.HasValue);
                Assert.Equal(QuicConnectionPhase.Discarded, runtime.TerminalState.Value.Phase);
                Assert.Contains(result.Effects, effect => effect is QuicConnectionDiscardConnectionStateEffect);
            }
            else
            {
                QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(
                    new($"203.0.113.{240 + variation}", RemotePort: 443));
                QuicConnectionPathIdentity validatedPath = new($"203.0.113.{250 + variation}", RemotePort: 443);
                byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

                Assert.False(runtime.HasValidatedPath);
                Assert.True(runtime.Transition(
                    new QuicConnectionPacketReceivedEvent(
                        ObservedAtTicks: 30 + variation,
                        validatedPath,
                        datagram),
                    nowTicks: 30 + variation).StateChanged);
                Assert.True(QuicPathMigrationRecoveryTestSupport.ValidatePath(
                    runtime,
                    validatedPath,
                    observedAtTicks: 40 + variation).StateChanged);
                Assert.True(runtime.HasValidatedPath);

                QuicConnectionPathIdentity failedPath = new($"203.0.113.{260 + variation}", RemotePort: 443);
                QuicConnectionTransitionResult result = runtime.Transition(
                    new QuicConnectionPathValidationFailedEvent(
                        ObservedAtTicks: 50 + variation,
                        failedPath,
                        IsAbandoned: true),
                    nowTicks: 50 + variation);

                Assert.False(result.StateChanged);
                Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
                Assert.Equal(QuicConnectionSendingMode.Ordinary, runtime.SendingMode);
                Assert.True(runtime.CanSendOrdinaryPackets);
                Assert.True(runtime.HasValidatedPath);
                Assert.Null(runtime.TerminalState);
                Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionDiscardConnectionStateEffect);
            }
        }
    }
}
