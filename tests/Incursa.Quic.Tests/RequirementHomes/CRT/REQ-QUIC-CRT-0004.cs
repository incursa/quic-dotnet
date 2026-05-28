// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0004")]
public sealed class REQ_QUIC_CRT_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RuntimePreservesOneSerializedProtocolStateOwnerAcrossDelegatedComponents()
    {
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());

        Assert.Equal(QuicConnectionPhase.Establishing, runtime.Phase);
        Assert.Equal(QuicConnectionSendingMode.Ordinary, runtime.SendingMode);
        Assert.True(runtime.CanSendOrdinaryPackets);

        QuicConnectionTransitionResult handshakeResult = runtime.Transition(
            new QuicConnectionPeerHandshakeTranscriptCompletedEvent(ObservedAtTicks: 1),
            nowTicks: 1);

        Assert.Equal(QuicConnectionPhase.Establishing, handshakeResult.PreviousPhase);
        Assert.Equal(QuicConnectionPhase.Active, handshakeResult.CurrentPhase);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.Equal(QuicConnectionSendingMode.Ordinary, runtime.SendingMode);
        Assert.True(runtime.CanSendOrdinaryPackets);

        QuicConnectionTransitionResult closeResult = runtime.Transition(
            new QuicConnectionLocalCloseRequestedEvent(
                ObservedAtTicks: 2,
                new QuicConnectionCloseMetadata(
                    TransportErrorCode: QuicTransportErrorCode.NoError,
                    ApplicationErrorCode: null,
                    TriggeringFrameType: 0x1c,
                    ReasonPhrase: "closing")),
            nowTicks: 2);

        Assert.Equal(QuicConnectionPhase.Active, closeResult.PreviousPhase);
        Assert.Equal(QuicConnectionPhase.Closing, closeResult.CurrentPhase);
        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.Equal(QuicConnectionSendingMode.CloseOnly, runtime.SendingMode);
        Assert.False(runtime.CanSendOrdinaryPackets);
    }
}
