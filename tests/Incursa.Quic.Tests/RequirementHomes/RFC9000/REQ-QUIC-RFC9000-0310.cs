// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S7-2-P3-S3-R01")]
public sealed class REQ_QUIC_RFC9000_0310
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientInitialFlightUsesOneDestinationConnectionIdBeforeServerPacketsArrive()
    {
        using QuicConnectionRuntime runtime = QuicS7P2FirstFlightConnectionIdTestSupport.CreateClientRuntime();

        QuicConnectionTransitionResult bootstrapResult =
            QuicS7P2FirstFlightConnectionIdTestSupport.BootstrapClientHandshake(runtime);

        QuicConnectionSendDatagramEffect[] initialEffects =
            QuicS17P2P3TestSupport.GetInitialSendEffects(bootstrapResult.Effects);
        Assert.NotEmpty(initialEffects);

        foreach (QuicConnectionSendDatagramEffect initialEffect in initialEffects)
        {
            QuicS7P2FirstFlightConnectionIdTestSupport.AssertLongHeaderConnectionIds(
                initialEffect.Datagram.Span,
                QuicS7P2FirstFlightConnectionIdTestSupport.InitialDestinationConnectionId,
                QuicS7P2FirstFlightConnectionIdTestSupport.InitialSourceConnectionId);
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClientInitialRetransmissionDoesNotSwitchToTheSourceConnectionIdBeforeServerPacketsArrive()
    {
        using QuicConnectionRuntime runtime = QuicS7P2FirstFlightConnectionIdTestSupport.CreateClientRuntime();

        _ = QuicS7P2FirstFlightConnectionIdTestSupport.BootstrapClientHandshake(runtime);
        QuicConnectionTransitionResult recoveryResult =
            QuicS7P2FirstFlightConnectionIdTestSupport.ExpireRecoveryTimer(runtime);

        QuicConnectionSendDatagramEffect[] initialEffects =
            QuicS17P2P3TestSupport.GetInitialSendEffects(recoveryResult.Effects);
        Assert.NotEmpty(initialEffects);

        foreach (QuicConnectionSendDatagramEffect initialEffect in initialEffects)
        {
            Assert.True(QuicPacketParser.TryParseLongHeader(initialEffect.Datagram.Span, out QuicLongHeaderPacket header));
            Assert.False(header.DestinationConnectionId.SequenceEqual(QuicS7P2FirstFlightConnectionIdTestSupport.InitialSourceConnectionId));
            Assert.True(header.DestinationConnectionId.SequenceEqual(QuicS7P2FirstFlightConnectionIdTestSupport.InitialDestinationConnectionId));
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ClientInitialRetransmissionKeepsTheMinimumLengthDestinationConnectionId()
    {
        using QuicConnectionRuntime runtime = QuicS7P2FirstFlightConnectionIdTestSupport.CreateClientRuntime();

        _ = QuicS7P2FirstFlightConnectionIdTestSupport.BootstrapClientHandshake(runtime);
        QuicConnectionTransitionResult recoveryResult =
            QuicS7P2FirstFlightConnectionIdTestSupport.ExpireRecoveryTimer(runtime);

        QuicConnectionSendDatagramEffect[] retransmittedInitials =
            QuicS17P2P3TestSupport.GetInitialSendEffects(recoveryResult.Effects);
        Assert.NotEmpty(retransmittedInitials);

        foreach (QuicConnectionSendDatagramEffect retransmittedInitial in retransmittedInitials)
        {
            Assert.True(QuicPacketParser.TryParseLongHeader(retransmittedInitial.Datagram.Span, out QuicLongHeaderPacket header));
            Assert.Equal(8, header.DestinationConnectionId.Length);
            Assert.True(header.DestinationConnectionId.SequenceEqual(QuicS7P2FirstFlightConnectionIdTestSupport.InitialDestinationConnectionId));
        }
    }
}
