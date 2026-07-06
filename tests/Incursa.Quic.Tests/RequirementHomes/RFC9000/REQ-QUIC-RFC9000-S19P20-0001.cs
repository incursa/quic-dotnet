// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P20-0001")]
public sealed class REQ_QUIC_RFC9000_S19P20_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseHandshakeDoneFrame_RecognizesTheHandshakeDoneType()
    {
        byte[] encoded = QuicFrameTestData.BuildHandshakeDoneFrame();

        Assert.True(QuicFrameCodec.TryParseHandshakeDoneFrame(encoded, out _, out int bytesConsumed));
        Assert.Equal(encoded.Length, bytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientTreatsReceivedHandshakeDoneAsHandshakeConfirmation()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();

        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.True(runtime.PeerHandshakeTranscriptCompleted);
        Assert.False(runtime.HandshakeConfirmed);

        QuicConnectionTransitionResult result = QuicPostHandshakeTicketTestSupport.ReceiveProtectedHandshakeDonePacket(
            runtime,
            observedAtTicks: 20);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.True(runtime.HandshakeConfirmed);
        Assert.Null(runtime.TerminalState);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P20-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void HandshakeDoneReceiveFuzz_ConfirmsHandshakeWithValidFrameAndTrailingPadding()
    {
        for (int paddingBytes = 0; paddingBytes < 8; paddingBytes++)
        {
            using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
            byte[] payload =
            [
                .. QuicFrameTestData.BuildHandshakeDoneFrame(),
                .. Enumerable.Repeat((byte)0x00, paddingBytes),
            ];
            byte[] protectedPacket = QuicS19P20HandshakeDoneTestSupport.CreateProtectedApplicationDataPacket(runtime, payload);
            QuicConnectionPathIdentity pathIdentity = runtime.ActivePath?.Identity
                ?? QuicS19P20HandshakeDoneTestSupport.PacketPathIdentity;

            QuicConnectionTransitionResult result = runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: 20 + paddingBytes,
                    pathIdentity,
                    protectedPacket),
                nowTicks: 20 + paddingBytes);

            Assert.True(result.StateChanged);
            Assert.True(runtime.HandshakeConfirmed);
            Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
            Assert.Null(runtime.TerminalState);
        }
    }
}
