// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S13P4P2P2-0002")]
public sealed class REQ_QUIC_RFC9000_S13P4P2P2_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2P2-0002")]
    [Trait("Category", "Positive")]
    public void PathValidationPacketsStopUsingEcnAfterValidationFailure()
    {
        QuicConnectionPathIdentity activePath = new(
            RemoteAddress: "203.0.113.90",
            LocalAddress: "198.51.100.90",
            RemotePort: 443,
            LocalPort: 61320);
        QuicConnectionPathIdentity newPath = new(
            RemoteAddress: "203.0.113.91",
            LocalAddress: "198.51.100.90",
            RemotePort: 443,
            LocalPort: 61320);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateServerRuntimeWithActivePath(activePath);

        QuicPathMigrationRecoveryTestSupport.DirtyRecoveryState(runtime);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                newPath,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 20);

        Assert.True(result.StateChanged);
        Assert.Contains(result.Effects, effect =>
            effect is QuicConnectionSendDatagramEffect sendDatagramEffect
            && sendDatagramEffect.PathIdentity == newPath
            && sendDatagramEffect.EcnMarking == QuicEcnMarking.NotEct
            && QuicFrameCodec.TryParsePathChallengeFrame(sendDatagramEffect.Datagram.Span, out _, out _));
    }
}
