// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S3P5_DeferredFuzzClosure
{
    private static readonly byte[] PacketConnectionId = [0x0A, 0x0B, 0x0C];

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P5-0004")]
    [Requirement("REQ-QUIC-RFC9000-S3P5-0005")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_StopSendingRequestsResetStreamFromReadyAndSendStates()
    {
        foreach ((bool bidirectional, int reservedBytes, ulong errorCode) in new[]
        {
            (false, 0, 0x11UL),
            (false, 7, 0x22UL),
            (true, 0, 0x33UL),
            (true, 13, 0x44UL),
        })
        {
            QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
                peerBidirectionalReceiveLimit: 32,
                peerUnidirectionalReceiveLimit: 32,
                localBidirectionalSendLimit: 32,
                localUnidirectionalSendLimit: 8,
                peerUnidirectionalStreamLimit: 8);
            Assert.True(state.TryOpenLocalStream(
                bidirectional,
                out QuicStreamId streamId,
                out QuicStreamsBlockedFrame blockedFrame));
            Assert.Equal(default, blockedFrame);

            if (reservedBytes > 0)
            {
                Assert.True(state.TryReserveSendCapacity(
                    streamId.Value,
                    offset: 0,
                    length: reservedBytes,
                    fin: false,
                    out QuicDataBlockedFrame dataBlockedFrame,
                    out QuicStreamDataBlockedFrame streamDataBlockedFrame,
                    out QuicTransportErrorCode reserveErrorCode));
                Assert.Equal(default, dataBlockedFrame);
                Assert.Equal(default, streamDataBlockedFrame);
                Assert.Equal(default, reserveErrorCode);
            }

            Assert.True(state.TryReceiveStopSendingFrame(
                new QuicStopSendingFrame(streamId.Value, errorCode),
                out QuicResetStreamFrame resetStreamFrame,
                out QuicTransportErrorCode stopSendingErrorCode));

            Assert.Equal(default, stopSendingErrorCode);
            Assert.Equal(streamId.Value, resetStreamFrame.StreamId);
            Assert.Equal(errorCode, resetStreamFrame.ApplicationProtocolErrorCode);
            Assert.Equal((ulong)reservedBytes, resetStreamFrame.FinalSize);
            Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshot));
            Assert.Equal(QuicStreamSendState.ResetSent, snapshot.SendState);
            Assert.True(snapshot.HasFinalSize);
            Assert.Equal((ulong)reservedBytes, snapshot.FinalSize);
            Assert.True(snapshot.HasSendAbortErrorCode);
            Assert.Equal(errorCode, snapshot.SendAbortErrorCode);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P5-0011")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public async Task Fuzz_LostStopSendingPacketsRemainRetransmittableWithOriginalFrameContent()
    {
        foreach (ulong applicationErrorCode in new[] { 0x11UL, 0x99UL, 0x1234UL })
        {
            using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
            List<QuicConnectionEffect> outboundEffects = [];
            runtime.SetLocalApiEventDispatcher(connectionEvent =>
            {
                QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
                outboundEffects.AddRange(transition.Effects);
                return true;
            });

            await runtime.AbortStreamReadsAsync(0, applicationErrorCode);

            QuicConnectionSendDatagramEffect sendEffect = Assert.Single(
                outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
            KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> stopSendingPacket =
                QuicS13AckPiggybackTestSupport.FindTrackedPacket(runtime, sendEffect.Datagram);
            QuicStopSendingFrame originalFrame = OpenStopSendingFrame(runtime, sendEffect.Datagram.Span);

            Assert.Equal(0UL, originalFrame.StreamId);
            Assert.Equal(applicationErrorCode, originalFrame.ApplicationProtocolErrorCode);
            Assert.True(runtime.SendRuntime.TryRegisterLoss(
                stopSendingPacket.Key.PacketNumberSpace,
                stopSendingPacket.Key.PacketNumber,
                handshakeConfirmed: true));
            Assert.Equal(1, runtime.SendRuntime.PendingRetransmissionCount);

            Assert.True(runtime.SendRuntime.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan retransmission));
            QuicStopSendingFrame retransmittedFrame = OpenStopSendingFrame(runtime, retransmission.PacketBytes.Span);

            Assert.Equal(originalFrame.StreamId, retransmittedFrame.StreamId);
            Assert.Equal(originalFrame.ApplicationProtocolErrorCode, retransmittedFrame.ApplicationProtocolErrorCode);
            Assert.False(runtime.SendRuntime.TryDequeueRetransmission(out _));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P5-0012")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ResetStreamCanTerminateOnlyTheLocalSendDirectionOfBidirectionalStreams()
    {
        foreach ((int reservedBytes, ulong expectedFinalSize) in new[]
        {
            (0, 0UL),
            (5, 5UL),
            (17, 17UL),
        })
        {
            QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
                peerBidirectionalReceiveLimit: 32,
                localBidirectionalSendLimit: 32);
            Assert.True(state.TryOpenLocalStream(
                bidirectional: true,
                out QuicStreamId streamId,
                out QuicStreamsBlockedFrame blockedFrame));
            Assert.Equal(default, blockedFrame);

            if (reservedBytes > 0)
            {
                Assert.True(state.TryReserveSendCapacity(
                    streamId.Value,
                    offset: 0,
                    length: reservedBytes,
                    fin: false,
                    out _,
                    out _,
                    out QuicTransportErrorCode reserveErrorCode));
                Assert.Equal(default, reserveErrorCode);
            }

            Assert.True(state.TryAbortLocalStreamWrites(
                streamId.Value,
                out ulong finalSize,
                out QuicTransportErrorCode abortErrorCode));

            Assert.Equal(default, abortErrorCode);
            Assert.Equal(expectedFinalSize, finalSize);
            Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshot));
            Assert.Equal(QuicStreamType.Bidirectional, snapshot.StreamType);
            Assert.Equal(QuicStreamSendState.ResetSent, snapshot.SendState);
            Assert.Equal(QuicStreamReceiveState.Recv, snapshot.ReceiveState);
            Assert.True(snapshot.HasFinalSize);
            Assert.Equal(expectedFinalSize, snapshot.FinalSize);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P5-0013")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public async Task Fuzz_AbortStreamReadsEmitsStopSendingWithoutResettingLocalWrites()
    {
        foreach (ulong applicationErrorCode in new[] { 0x01UL, 0x99UL, 0x4000UL })
        {
            using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
            List<QuicConnectionEffect> outboundEffects = [];
            List<QuicStreamNotification> notifications = [];
            runtime.SetLocalApiEventDispatcher(connectionEvent =>
            {
                QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
                outboundEffects.AddRange(transition.Effects);
                return true;
            });
            runtime.RegisterStreamObserver(0, notifications.Add);

            await runtime.AbortStreamReadsAsync(0, applicationErrorCode);

            QuicConnectionSendDatagramEffect sendEffect = Assert.Single(
                outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
            byte[] plaintext = QuicS13AckPiggybackTestSupport.OpenOutgoingApplicationPayload(runtime, sendEffect);

            Assert.True(QuicStreamControlFrameTestSupport.TryFindStopSendingFrame(
                plaintext,
                out QuicStopSendingFrame stopSendingFrame,
                out _,
                out _));
            Assert.Equal(0UL, stopSendingFrame.StreamId);
            Assert.Equal(applicationErrorCode, stopSendingFrame.ApplicationProtocolErrorCode);
            Assert.False(QuicStreamControlFrameTestSupport.TryFindResetStreamFrame(
                plaintext,
                out _,
                out _,
                out _));

            QuicStreamNotification notification = Assert.Single(notifications);
            Assert.Equal(QuicStreamNotificationKind.ReadAborted, notification.Kind);
        }
    }

    private static QuicStopSendingFrame OpenStopSendingFrame(
        QuicConnectionRuntime runtime,
        ReadOnlySpan<byte> datagram)
    {
        QuicHandshakeFlowCoordinator coordinator = new(PacketConnectionId);
        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            datagram,
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength));
        Assert.True(QuicStreamControlFrameTestSupport.TryFindStopSendingFrame(
            openedPacket.AsSpan(payloadOffset, payloadLength),
            out QuicStopSendingFrame stopSendingFrame,
            out _,
            out _));

        return stopSendingFrame;
    }
}
