// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S2P4_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S2P4-0003")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_StreamWritesReserveFlowControlCreditBeforeTheyCanAdvanceSendState()
    {
        foreach ((ulong streamCredit, int writeLength, bool expectedReserved) in new[]
        {
            (1UL, 1, true),
            (8UL, 8, true),
            (16UL, 17, false),
            (31UL, 31, true),
            (31UL, 32, false),
        })
        {
            QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
                connectionSendLimit: 128,
                peerBidirectionalReceiveLimit: 8,
                localBidirectionalSendLimit: streamCredit);
            Assert.True(state.TryOpenLocalStream(
                bidirectional: true,
                out QuicStreamId streamId,
                out QuicStreamsBlockedFrame streamsBlockedFrame));
            Assert.Equal(default, streamsBlockedFrame);

            bool reserved = state.TryReserveSendCapacity(
                streamId.Value,
                offset: 0,
                length: writeLength,
                fin: false,
                out QuicDataBlockedFrame dataBlockedFrame,
                out QuicStreamDataBlockedFrame streamDataBlockedFrame,
                out QuicTransportErrorCode errorCode);

            Assert.Equal(expectedReserved, reserved);
            Assert.Equal(default, dataBlockedFrame);
            Assert.Equal(default, errorCode);
            Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshot));

            if (expectedReserved)
            {
                Assert.Equal(default, streamDataBlockedFrame);
                Assert.Equal((ulong)writeLength, snapshot.UniqueBytesSent);
                Assert.Equal(QuicStreamSendState.Send, snapshot.SendState);
            }
            else
            {
                Assert.Equal(streamId.Value, streamDataBlockedFrame.StreamId);
                Assert.Equal(streamCredit, streamDataBlockedFrame.MaximumStreamData);
                Assert.Equal(0UL, snapshot.UniqueBytesSent);
            }
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S2P4-0004")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public async Task Fuzz_CompleteWritesEmitsFinOnlyStreamFramesForWritableOutboundStreams()
    {
        foreach (QuicStreamType streamType in new[] { QuicStreamType.Bidirectional, QuicStreamType.Unidirectional })
        {
            using QuicConnectionRuntime runtime =
                QuicS13ApplicationSendDelayTestSupport.CreateConfirmedClientRuntimeWithValidatedActivePath();
            List<QuicConnectionEffect> outboundEffects = [];
            runtime.SetLocalApiEventDispatcher(connectionEvent =>
            {
                QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
                outboundEffects.AddRange(transition.Effects);
                return true;
            });

            await using QuicStream stream = await runtime.OpenOutboundStreamAsync(streamType);
            outboundEffects.Clear();

            await stream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5));
            await stream.WritesClosed.WaitAsync(TimeSpan.FromSeconds(5));

            QuicConnectionSendDatagramEffect sendEffect = Assert.Single(
                outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
            byte[] payload = QuicS13AckPiggybackTestSupport.OpenOutgoingApplicationPayload(runtime, sendEffect);
            QuicStreamFrame frame = QuicS13RetransmissionTestSupport.AssertSingleStreamFrame(payload);

            Assert.Equal((ulong)stream.Id, frame.StreamId.Value);
            Assert.Equal(0UL, frame.Offset);
            Assert.Equal(0, frame.StreamDataLength);
            Assert.True(frame.IsFin);
            Assert.False(stream.CanWrite);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S2P4-0005")]
    [Requirement("REQ-QUIC-RFC9000-S2P4-0008")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public async Task Fuzz_AbortWriteEmitsResetStreamWithFinalSizeAndWriteAbortNotification()
    {
        foreach ((int payloadLength, ulong errorCode) in new[] { (0, 0x11UL), (5, 0x22UL), (13, 0x1234UL) })
        {
            using QuicConnectionRuntime runtime =
                QuicS13ApplicationSendDelayTestSupport.CreateConfirmedClientRuntimeWithValidatedActivePath(
                    connectionSendLimit: 128,
                    localBidirectionalSendLimit: 128);
            List<QuicConnectionEffect> outboundEffects = [];
            List<QuicStreamNotification> notifications = [];
            runtime.SetLocalApiEventDispatcher(connectionEvent =>
            {
                QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
                outboundEffects.AddRange(transition.Effects);
                return true;
            });

            await using QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
            runtime.RegisterStreamObserver((ulong)stream.Id, notifications.Add);
            outboundEffects.Clear();

            if (payloadLength > 0)
            {
                byte[] payload = Enumerable.Range(0, payloadLength).Select(static value => (byte)(0x40 + value)).ToArray();
                await stream.WriteAsync(payload, 0, payload.Length).WaitAsync(TimeSpan.FromSeconds(5));
                outboundEffects.Clear();
            }

            stream.Abort(QuicAbortDirection.Write, (long)errorCode);

            Assert.True(QuicStreamControlFrameTestSupport.TryFindProtectedResetStreamFrame(
                runtime,
                outboundEffects.OfType<QuicConnectionSendDatagramEffect>(),
                out QuicResetStreamFrame resetStreamFrame));
            Assert.Equal((ulong)stream.Id, resetStreamFrame.StreamId);
            Assert.Equal(errorCode, resetStreamFrame.ApplicationProtocolErrorCode);
            Assert.Equal((ulong)payloadLength, resetStreamFrame.FinalSize);
            Assert.False(stream.CanWrite);
            Assert.True(stream.CanRead);

            QuicStreamNotification notification = Assert.Single(notifications);
            Assert.Equal(QuicStreamNotificationKind.WriteAborted, notification.Kind);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S2P4-0007")]
    [Requirement("REQ-QUIC-RFC9000-S2P4-0008")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public async Task Fuzz_AbortReadEmitsStopSendingWithReadAbortNotificationWithoutClosingWrites()
    {
        foreach (ulong errorCode in new[] { 0x01UL, 0x66UL, 0x4000UL })
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

            await using QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
            runtime.RegisterStreamObserver((ulong)stream.Id, notifications.Add);
            outboundEffects.Clear();

            stream.Abort(QuicAbortDirection.Read, (long)errorCode);

            Assert.True(QuicStreamControlFrameTestSupport.TryFindProtectedStopSendingFrame(
                runtime,
                outboundEffects.OfType<QuicConnectionSendDatagramEffect>(),
                out QuicStopSendingFrame stopSendingFrame));
            Assert.Equal((ulong)stream.Id, stopSendingFrame.StreamId);
            Assert.Equal(errorCode, stopSendingFrame.ApplicationProtocolErrorCode);
            Assert.False(stream.CanRead);
            Assert.True(stream.CanWrite);

            QuicStreamNotification notification = Assert.Single(notifications);
            Assert.Equal(QuicStreamNotificationKind.ReadAborted, notification.Kind);
        }
    }
}
