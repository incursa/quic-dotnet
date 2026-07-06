// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9002_S7_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S7-0002")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AckOnlyPacketsDoNotCountTowardBytesInFlight()
    {
        foreach (ulong packetSizeBytes in RepresentativePacketSizes())
        {
            QuicCongestionControlState ackOnlyState = new();
            ulong baselineBytesInFlight = ackOnlyState.BytesInFlightBytes;

            ackOnlyState.RegisterPacketSent(packetSizeBytes, isAckOnlyPacket: true);

            Assert.Equal(baselineBytesInFlight, ackOnlyState.BytesInFlightBytes);

            QuicCongestionControlState congestedState = new();
            congestedState.RegisterPacketSent(congestedState.CongestionWindowBytes);
            ulong congestedBaselineBytesInFlight = congestedState.BytesInFlightBytes;

            congestedState.RegisterPacketSent(packetSizeBytes, isAckOnlyPacket: true);

            Assert.Equal(congestedBaselineBytesInFlight, congestedState.BytesInFlightBytes);

            QuicCongestionControlState congestionControlledState = new();
            congestionControlledState.RegisterPacketSent(packetSizeBytes, isAckOnlyPacket: false);

            Assert.Equal(packetSizeBytes, congestionControlledState.BytesInFlightBytes);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S7-0003")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AckOnlyPacketsBypassCongestionControl()
    {
        foreach (ulong packetSizeBytes in RepresentativePacketSizes())
        {
            QuicCongestionControlState state = new();
            state.RegisterPacketSent(state.CongestionWindowBytes);

            Assert.True(state.CanSend(packetSizeBytes, isAckOnlyPacket: true, isProbePacket: false));
            Assert.False(state.CanSend(packetSizeBytes, isAckOnlyPacket: false, isProbePacket: false));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S7-0005")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PathValidationDoesNotMutateActivePathCongestionState()
    {
        foreach ((QuicConnectionPathIdentity activePath, QuicConnectionPathIdentity candidatePath) in new[]
        {
            (
                new QuicConnectionPathIdentity("203.0.113.50", "198.51.100.50", RemotePort: 443, LocalPort: 61234),
                new QuicConnectionPathIdentity("203.0.113.51", "198.51.100.50", RemotePort: 443, LocalPort: 61234)),
            (
                new QuicConnectionPathIdentity("203.0.113.52", "198.51.100.52", RemotePort: 443, LocalPort: 61234),
                new QuicConnectionPathIdentity("203.0.113.53", "198.51.100.53", RemotePort: 8443, LocalPort: 61235)),
            (
                new QuicConnectionPathIdentity("203.0.113.54", "198.51.100.54", RemotePort: 65535, LocalPort: 49152),
                new QuicConnectionPathIdentity("203.0.113.55", "198.51.100.55", RemotePort: 443, LocalPort: 49153)),
        })
        {
            using QuicConnectionRuntime runtime =
                QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithConfirmedHandshakeAndActivePath(activePath);
            QuicPathMigrationRecoveryTestSupport.DirtyRecoveryState(runtime);
            QuicPathMigrationRecoverySnapshot baseline =
                QuicPathMigrationRecoveryTestSupport.CaptureRecoveryState(runtime);

            QuicConnectionTransitionResult result = runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: 10,
                    candidatePath,
                    new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
                nowTicks: 10);

            Assert.True(result.StateChanged);
            Assert.True(runtime.ActivePath.HasValue);
            Assert.Equal(activePath, runtime.ActivePath.Value.Identity);
            Assert.Equal(baseline, QuicPathMigrationRecoveryTestSupport.CaptureRecoveryState(runtime));
            Assert.Contains(result.Effects, effect =>
                effect is QuicConnectionSendDatagramEffect send
                && send.PathIdentity == candidatePath
                && QuicFrameCodec.TryParsePathChallengeFrame(send.Datagram.Span, out _, out _));
        }
    }

    private static ulong[] RepresentativePacketSizes()
    {
        QuicCongestionControlState state = new();
        return
        [
            1,
            64,
            1_200,
            state.CongestionWindowBytes,
            state.CongestionWindowBytes + 1,
        ];
    }
}
