// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P2P2-0025")]
public sealed class REQ_QUIC_RFC9000_S17P2P2_0025
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryHandleInitialPacketReceived_DiscardsInitialPacketsContainingResetStreamFrames()
    {
        using QuicConnectionRuntime runtime = QuicS17P2P2TestSupport.CreateServerRuntime();
        QuicConnectionPathIdentity path = new("203.0.113.70", RemotePort: 443);
        byte[] resetStreamPayload = QuicFrameTestData.BuildResetStreamFrame(new QuicResetStreamFrame(0, 1, 0));
        byte[] protectedPacket = QuicS17P2P2TestSupport.CreateProtectedClientInitialPacket(resetStreamPayload);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 0,
                path,
                protectedPacket),
            nowTicks: 0);

        Assert.True(result.StateChanged || runtime.TerminalState is null);
        if (runtime.TerminalState is { } terminalState)
        {
            Assert.Equal(QuicConnectionCloseOrigin.Local, terminalState.Origin);
            Assert.Equal(QuicTransportErrorCode.ProtocolViolation, terminalState.Close.TransportErrorCode);
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryHandleInitialPacketReceived_DiscardsOtherFramesBeforeProcessingLaterCrypto()
    {
        using QuicConnectionRuntime runtime = QuicS17P2P2TestSupport.CreateServerRuntime();
        QuicConnectionPathIdentity path = new("203.0.113.70", RemotePort: 443);
        byte[] resetStreamPayload = QuicFrameTestData.BuildResetStreamFrame(new QuicResetStreamFrame(0, 1, 0));
        byte[] cryptoPayload = QuicFrameTestData.BuildCryptoFrame(
            new QuicCryptoFrame(0, QuicS17P2P2TestSupport.CreateSequentialBytes(0x60, 8)));
        byte[] plaintextPayload = new byte[resetStreamPayload.Length + cryptoPayload.Length];
        resetStreamPayload.CopyTo(plaintextPayload, 0);
        cryptoPayload.CopyTo(plaintextPayload.AsSpan(resetStreamPayload.Length));
        byte[] protectedPacket = QuicS17P2P2TestSupport.CreateProtectedClientInitialPacket(plaintextPayload);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 1,
                path,
                protectedPacket),
            nowTicks: 1);

        Assert.True(result.StateChanged || runtime.TerminalState is null);
        if (runtime.TerminalState is { } terminalState)
        {
            Assert.Equal(QuicConnectionCloseOrigin.Local, terminalState.Origin);
            Assert.Equal(QuicTransportErrorCode.ProtocolViolation, terminalState.Close.TransportErrorCode);
        }
    }
}
