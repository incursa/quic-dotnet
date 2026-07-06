// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S3-0001")]
public sealed class REQ_QUIC_RFC9000_S3_0001
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryOpenLocalStream_UsesSendStateMachineForLocalUnidirectionalStreams()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState();

        Assert.True(state.TryOpenLocalStream(bidirectional: false, out QuicStreamId streamId, out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamSendState.Ready, snapshot.SendState);
        Assert.Equal(QuicStreamReceiveState.None, snapshot.ReceiveState);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReceiveStreamFrame_RejectsLocalUnidirectionalStreamsWithoutReceiveParts()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState();

        Assert.True(state.TryOpenLocalStream(bidirectional: false, out QuicStreamId streamId, out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamReceiveState.None, snapshot.ReceiveState);

        byte[] packet = QuicStreamTestData.BuildStreamFrame(0x0E, streamId.Value, [0x10], offset: 0);
        Assert.True(QuicStreamParser.TryParseStreamFrame(packet, out QuicStreamFrame frame));

        Assert.False(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(QuicTransportErrorCode.StreamStateError, errorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_LocalUnidirectionalStreamsUseOnlyTheSendStateMachine()
    {
        LocalUnidirectionalStreamCase[] scenarios =
        [
            new(IsServer: false, SendLength: 0, ReceivePayload: [0x10]),
            new(IsServer: false, SendLength: 1, ReceivePayload: [0x20]),
            new(IsServer: true, SendLength: 3, ReceivePayload: [0x30, 0x31]),
            new(IsServer: true, SendLength: 7, ReceivePayload: [0x40, 0x41, 0x42]),
        ];

        foreach (LocalUnidirectionalStreamCase scenario in scenarios)
        {
            QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
                isServer: scenario.IsServer,
                connectionSendLimit: 64,
                localUnidirectionalSendLimit: 64);

            Assert.True(state.TryOpenLocalStream(bidirectional: false, out QuicStreamId streamId, out QuicStreamsBlockedFrame blockedFrame));
            Assert.Equal(default, blockedFrame);

            Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot openedSnapshot));
            Assert.Equal(QuicStreamSendState.Ready, openedSnapshot.SendState);
            Assert.Equal(QuicStreamReceiveState.None, openedSnapshot.ReceiveState);

            Assert.True(state.TryReserveSendCapacity(
                streamId.Value,
                offset: 0,
                length: scenario.SendLength,
                fin: scenario.SendLength == 0,
                out QuicDataBlockedFrame dataBlockedFrame,
                out QuicStreamDataBlockedFrame streamDataBlockedFrame,
                out QuicTransportErrorCode errorCode));
            Assert.Equal(default, dataBlockedFrame);
            Assert.Equal(default, streamDataBlockedFrame);
            Assert.Equal(default, errorCode);

            Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot sendSnapshot));
            Assert.Equal(
                scenario.SendLength == 0 ? QuicStreamSendState.DataSent : QuicStreamSendState.Send,
                sendSnapshot.SendState);
            Assert.Equal(QuicStreamReceiveState.None, sendSnapshot.ReceiveState);

            byte[] packet = QuicStreamTestData.BuildStreamFrame(0x0E, streamId.Value, scenario.ReceivePayload, offset: 0);
            Assert.True(QuicStreamParser.TryParseStreamFrame(packet, out QuicStreamFrame frame));

            Assert.False(state.TryReceiveStreamFrame(frame, out errorCode));
            Assert.Equal(QuicTransportErrorCode.StreamStateError, errorCode);

            Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot rejectedSnapshot));
            Assert.Equal(sendSnapshot.SendState, rejectedSnapshot.SendState);
            Assert.Equal(QuicStreamReceiveState.None, rejectedSnapshot.ReceiveState);
        }
    }

    private readonly record struct LocalUnidirectionalStreamCase(
        bool IsServer,
        int SendLength,
        byte[] ReceivePayload);
}
