// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S3-0003")]
public sealed class REQ_QUIC_RFC9000_S3_0003
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3-0003")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReserveSendCapacity_AdvancesOnlyTheSendPartOfABidirectionalStream()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 16,
            connectionSendLimit: 16);

        Assert.True(state.TryOpenLocalStream(bidirectional: true, out QuicStreamId streamId, out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot readySnapshot));
        Assert.Equal(QuicStreamSendState.Ready, readySnapshot.SendState);
        Assert.Equal(QuicStreamReceiveState.Recv, readySnapshot.ReceiveState);

        Assert.True(state.TryReserveSendCapacity(
            streamId.Value,
            offset: 0,
            length: 1,
            fin: false,
            out QuicDataBlockedFrame dataBlockedFrame,
            out QuicStreamDataBlockedFrame streamDataBlockedFrame,
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, dataBlockedFrame);
        Assert.Equal(default, streamDataBlockedFrame);
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot sendSnapshot));
        Assert.Equal(QuicStreamSendState.Send, sendSnapshot.SendState);
        Assert.Equal(QuicStreamReceiveState.Recv, sendSnapshot.ReceiveState);

        byte[] packet = QuicStreamTestData.BuildStreamFrame(0x0F, streamId.Value, [0xAA]);
        Assert.True(QuicStreamParser.TryParseStreamFrame(packet, out QuicStreamFrame frame));

        Assert.True(state.TryReceiveStreamFrame(frame, out errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot completedSnapshot));
        Assert.Equal(QuicStreamSendState.Send, completedSnapshot.SendState);
        Assert.Equal(QuicStreamReceiveState.DataRecvd, completedSnapshot.ReceiveState);
        Assert.True(completedSnapshot.HasFinalSize);
        Assert.Equal(1UL, completedSnapshot.FinalSize);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3-0003")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryReceiveStreamFrame_AdvancesOnlyTheReceivePartOfABidirectionalStream()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 16,
            connectionSendLimit: 16);

        Assert.True(state.TryOpenLocalStream(bidirectional: true, out QuicStreamId streamId, out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        byte[] packet = QuicStreamTestData.BuildStreamFrame(0x0F, streamId.Value, [0x11, 0x22]);
        Assert.True(QuicStreamParser.TryParseStreamFrame(packet, out QuicStreamFrame frame));

        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamSendState.Ready, snapshot.SendState);
        Assert.Equal(QuicStreamReceiveState.DataRecvd, snapshot.ReceiveState);
        Assert.True(snapshot.HasFinalSize);
        Assert.Equal(2UL, snapshot.FinalSize);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3-0003")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_BidirectionalStreamsAdvanceSendAndReceivePartsIndependently()
    {
        BidirectionalStreamStateCase[] scenarios =
        [
            new(IsServer: false, SendLength: 0, SendFin: true, ReceivePayload: [0x10], ReceiveFin: false),
            new(IsServer: false, SendLength: 1, SendFin: false, ReceivePayload: [0x20, 0x21], ReceiveFin: true),
            new(IsServer: true, SendLength: 3, SendFin: false, ReceivePayload: [0x30], ReceiveFin: false),
            new(IsServer: true, SendLength: 5, SendFin: true, ReceivePayload: [0x40, 0x41, 0x42], ReceiveFin: true),
        ];

        foreach (BidirectionalStreamStateCase scenario in scenarios)
        {
            QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
                isServer: scenario.IsServer,
                connectionReceiveLimit: 64,
                connectionSendLimit: 64,
                localBidirectionalSendLimit: 64);

            Assert.True(state.TryOpenLocalStream(bidirectional: true, out QuicStreamId streamId, out QuicStreamsBlockedFrame blockedFrame));
            Assert.Equal(default, blockedFrame);

            Assert.True(state.TryReserveSendCapacity(
                streamId.Value,
                offset: 0,
                length: scenario.SendLength,
                fin: scenario.SendFin,
                out QuicDataBlockedFrame dataBlockedFrame,
                out QuicStreamDataBlockedFrame streamDataBlockedFrame,
                out QuicTransportErrorCode errorCode));
            Assert.Equal(default, dataBlockedFrame);
            Assert.Equal(default, streamDataBlockedFrame);
            Assert.Equal(default, errorCode);

            Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot afterSendSnapshot));
            Assert.Equal(
                scenario.SendFin ? QuicStreamSendState.DataSent : QuicStreamSendState.Send,
                afterSendSnapshot.SendState);
            Assert.Equal(QuicStreamReceiveState.Recv, afterSendSnapshot.ReceiveState);

            byte[] packet = QuicStreamTestData.BuildStreamFrame(
                scenario.ReceiveFin ? (byte)0x0F : (byte)0x0E,
                streamId.Value,
                scenario.ReceivePayload,
                offset: 0);
            Assert.True(QuicStreamParser.TryParseStreamFrame(packet, out QuicStreamFrame frame));

            Assert.True(state.TryReceiveStreamFrame(frame, out errorCode));
            Assert.Equal(default, errorCode);

            Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot afterReceiveSnapshot));
            Assert.Equal(afterSendSnapshot.SendState, afterReceiveSnapshot.SendState);
            Assert.Equal(
                scenario.ReceiveFin ? QuicStreamReceiveState.DataRecvd : QuicStreamReceiveState.Recv,
                afterReceiveSnapshot.ReceiveState);
            if (scenario.ReceiveFin)
            {
                Assert.True(afterReceiveSnapshot.HasFinalSize);
                Assert.Equal((ulong)scenario.ReceivePayload.Length, afterReceiveSnapshot.FinalSize);
            }
        }
    }

    private readonly record struct BidirectionalStreamStateCase(
        bool IsServer,
        int SendLength,
        bool SendFin,
        byte[] ReceivePayload,
        bool ReceiveFin);
}
