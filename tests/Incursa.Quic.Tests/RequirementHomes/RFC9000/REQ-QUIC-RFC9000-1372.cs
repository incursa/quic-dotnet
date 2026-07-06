// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-1372")]
public sealed class REQ_QUIC_RFC9000_1372
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerTreatsReceivedHandshakeDoneAsAProtocolViolation()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime();

        QuicConnectionTransitionResult result = QuicPostHandshakeTicketTestSupport.ReceiveProtectedHandshakeDonePacket(
            runtime,
            observedAtTicks: 20);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.NotNull(runtime.TerminalState);
        Assert.Equal(QuicConnectionCloseOrigin.Local, runtime.TerminalState!.Value.Origin);
        Assert.Equal(QuicTransportErrorCode.ProtocolViolation, runtime.TerminalState.Value.Close.TransportErrorCode);
        Assert.Equal(0x1EUL, runtime.TerminalState.Value.Close.TriggeringFrameType);
        Assert.Contains(result.Effects, effect => effect is QuicConnectionSendDatagramEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerKeepsTheConnectionOpenWhenTheProtectedPacketDoesNotContainHandshakeDone()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime();
        byte[] protectedPacket = QuicS19P20HandshakeDoneTestSupport.CreateProtectedApplicationDataPacket(
            runtime,
            QuicFrameTestData.BuildPingFrame());
        QuicConnectionPathIdentity pathIdentity = runtime.ActivePath?.Identity
            ?? QuicS19P20HandshakeDoneTestSupport.PacketPathIdentity;

        _ = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                pathIdentity,
                protectedPacket),
            nowTicks: 20);

        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.Null(runtime.TerminalState);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ServerTreatsReceivedHandshakeDone_FuzzAsProtocolViolationAcrossPacketTimes()
    {
        for (long observedAtTicks = 20; observedAtTicks < 24; observedAtTicks++)
        {
            using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime();

            QuicConnectionTransitionResult result = QuicPostHandshakeTicketTestSupport.ReceiveProtectedHandshakeDonePacket(
                runtime,
                observedAtTicks);

            Assert.True(result.StateChanged);
            Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
            Assert.NotNull(runtime.TerminalState);
            Assert.Equal(QuicTransportErrorCode.ProtocolViolation, runtime.TerminalState!.Value.Close.TransportErrorCode);
            Assert.Equal(0x1EUL, runtime.TerminalState.Value.Close.TriggeringFrameType);
        }
    }
}
