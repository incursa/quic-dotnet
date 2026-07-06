// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9002_SBP7_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9002-SBP7-0002")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_EcnCongestionRecoveryUsesLargestAcknowledgedPacketSendTime()
    {
        foreach ((QuicPacketNumberSpace packetNumberSpace, ulong reportedCeCount, ulong largestAcknowledgedSentAtMicros) in new[]
        {
            (QuicPacketNumberSpace.Initial, 1UL, 0UL),
            (QuicPacketNumberSpace.Handshake, 2UL, 1UL),
            (QuicPacketNumberSpace.ApplicationData, 3UL, 4_200UL),
            (QuicPacketNumberSpace.ApplicationData, ulong.MaxValue, 500_000UL),
        })
        {
            QuicCongestionControlState state = new();
            state.RegisterPacketSent(12_000);

            Assert.True(state.TryProcessEcn(
                packetNumberSpace,
                reportedCeCount,
                largestAcknowledgedSentAtMicros,
                pathValidated: true));

            Assert.Equal(largestAcknowledgedSentAtMicros, state.RecoveryStartTimeMicros);
            Assert.Equal(6_000UL, state.CongestionWindowBytes);
        }
    }
}
