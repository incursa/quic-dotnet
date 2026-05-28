// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-1246")]
public sealed class REQ_QUIC_RFC9000_1246
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerTreatsReceivedNewTokenFrameAsProtocolViolation()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime();
        byte[] encoded = QuicS19P7NewTokenFrameTestSupport.BuildNewTokenFrame(
            QuicS19P7NewTokenFrameTestSupport.RepresentativeToken);

        QuicConnectionTransitionResult result = QuicS19P7NewTokenFrameTestSupport.ReceiveProtectedApplicationPacket(
            runtime,
            encoded,
            observedAtTicks: 20);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.NotNull(runtime.TerminalState);
        Assert.Equal(QuicConnectionCloseOrigin.Local, runtime.TerminalState!.Value.Origin);
        Assert.Equal(QuicTransportErrorCode.ProtocolViolation, runtime.TerminalState.Value.Close.TransportErrorCode);
        Assert.Equal(0x07UL, runtime.TerminalState.Value.Close.TriggeringFrameType);
        Assert.Contains(result.Effects, effect => effect is QuicConnectionSendDatagramEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClientDoesNotTreatReceivedNonEmptyNewTokenFrameAsProtocolViolation()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        byte[] encoded = QuicS19P7NewTokenFrameTestSupport.BuildNewTokenFrame(
            QuicS19P7NewTokenFrameTestSupport.RepresentativeToken);

        _ = QuicS19P7NewTokenFrameTestSupport.ReceiveProtectedApplicationPacket(
            runtime,
            encoded,
            observedAtTicks: 20);

        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.Null(runtime.TerminalState);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ServerTreatsMalformedNewTokenFrameAsProtocolViolationInsteadOfFrameEncodingError()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime();
        byte[] encoded = QuicS19P7NewTokenFrameTestSupport.BuildNewTokenFrame(Array.Empty<byte>());

        QuicConnectionTransitionResult result = QuicS19P7NewTokenFrameTestSupport.ReceiveProtectedApplicationPacket(
            runtime,
            encoded,
            observedAtTicks: 20);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.Equal(QuicTransportErrorCode.ProtocolViolation, runtime.TerminalState!.Value.Close.TransportErrorCode);
        Assert.Equal(0x07UL, runtime.TerminalState.Value.Close.TriggeringFrameType);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzServerReceiptOfNewTokenAlwaysClosesWithProtocolViolation()
    {
        Random random = new(0x5197_0010);
        for (int iteration = 0; iteration < 8; iteration++)
        {
            using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime();
            byte[] token = new byte[random.Next(1, 16)];
            random.NextBytes(token);
            byte[] encoded = QuicS19P7NewTokenFrameTestSupport.BuildNewTokenFrame(token);

            QuicConnectionTransitionResult result = QuicS19P7NewTokenFrameTestSupport.ReceiveProtectedApplicationPacket(
                runtime,
                encoded,
                observedAtTicks: 20 + iteration);

            Assert.True(result.StateChanged);
            Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
            Assert.Equal(QuicTransportErrorCode.ProtocolViolation, runtime.TerminalState!.Value.Close.TransportErrorCode);
            Assert.Equal(0x07UL, runtime.TerminalState.Value.Close.TriggeringFrameType);
        }
    }
}
