// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_AckLossRetransmission_DeferredFuzzClosure
{
    private static readonly byte[] PacketConnectionId = [0x0A, 0x0B, 0x0C];

    private static readonly byte[] PacketSourceConnectionId = [0x01, 0x02, 0x03, 0x04];

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0749")]
    [Requirement("REQ-QUIC-RFC9000-0753")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void AckProcessingFuzz_RecordsAckEligibilityOnlyAfterProtectionAndFramesAreProcessed()
    {
        Assert.True(QuicS12P3TestSupport.TryCreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt,
            out QuicTlsPacketProtectionMaterial material));

        QuicHandshakeFlowCoordinator coordinator = CreateApplicationCoordinator();
        QuicConnectionStreamState streamState = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 128,
            peerBidirectionalReceiveLimit: 128);
        QuicAckGenerationState ackState = new();
        List<ulong> processedPacketNumbers = [];

        foreach ((ulong StreamId, byte[] StreamData, ulong ReceivedAtMicros) testCase in new (ulong, byte[], ulong)[]
        {
            (1UL, [0x11, 0x12], 1_000UL),
            (5UL, [0x21, 0x22, 0x23], 1_200UL),
            (9UL, [0x31], 1_400UL),
        })
        {
            byte[] applicationPayload =
            [
                .. QuicFrameTestData.BuildPingFrame(),
                .. QuicStreamTestData.BuildStreamFrame(0x0E, testCase.StreamId, testCase.StreamData, offset: 0),
            ];

            Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
                applicationPayload,
                material,
                out ulong packetNumber,
                out byte[] protectedPacket));
            Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
                protectedPacket,
                material,
                out byte[] openedPacket,
                out int payloadOffset,
                out int payloadLength,
                out _));

            ReadOnlySpan<byte> openedPayload = openedPacket.AsSpan(payloadOffset, payloadLength);
            Assert.True(QuicFrameCodec.TryParsePingFrame(openedPayload, out int pingBytesConsumed));
            Assert.True(QuicStreamParser.TryParseStreamFrame(openedPayload[pingBytesConsumed..], out QuicStreamFrame streamFrame));
            Assert.True(streamState.TryReceiveStreamFrame(streamFrame, out QuicTransportErrorCode errorCode));
            Assert.Equal(default, errorCode);

            ackState.RecordProcessedPacket(
                QuicPacketNumberSpace.ApplicationData,
                packetNumber,
                ackEliciting: true,
                testCase.ReceivedAtMicros);
            processedPacketNumbers.Add(packetNumber);
        }

        Assert.True(ackState.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 2_000,
            out QuicAckFrame frame));

        foreach (ulong packetNumber in processedPacketNumbers)
        {
            Assert.True(AckFrameCoversPacketNumber(frame, packetNumber));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0789")]
    [Requirement("REQ-QUIC-RFC9000-0795")]
    [Requirement("REQ-QUIC-RFC9000-0799")]
    [Requirement("REQ-QUIC-RFC9000-0816")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void RetransmissionPlanFuzz_PreservesRepairPayloadsAndRemovesAcknowledgedRepairs()
    {
        foreach ((ulong PacketNumber, byte[] PacketBytes, Action<byte[]> VerifyPacketBytes) testCase in new (ulong, byte[], Action<byte[]>)[]
        {
            (10UL, QuicFrameTestData.BuildCryptoFrame(new QuicCryptoFrame(0, [0xA0, 0xA1, 0xA2])), VerifyCryptoFrame),
            (11UL, QuicFrameTestData.BuildResetStreamFrame(new QuicResetStreamFrame(1, 0x99, 4)), VerifyResetStreamFrame),
            (12UL, QuicFrameTestData.BuildMaxDataFrame(new QuicMaxDataFrame(128)), VerifyMaxDataFrame),
        })
        {
            QuicConnectionSendRuntime runtime = new();
            runtime.TrackSentPacket(new QuicConnectionSentPacket(
                QuicPacketNumberSpace.ApplicationData,
                testCase.PacketNumber,
                PayloadBytes: (ulong)testCase.PacketBytes.Length,
                SentAtMicros: 1_000 + testCase.PacketNumber,
                AckEliciting: true,
                Retransmittable: true,
                PacketBytes: testCase.PacketBytes));

            Assert.True(runtime.TryRegisterLoss(
                QuicPacketNumberSpace.ApplicationData,
                testCase.PacketNumber,
                handshakeConfirmed: true));
            Assert.Equal(1, runtime.PendingRetransmissionCount);

            Assert.True(runtime.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan retransmission));
            Assert.Equal(testCase.PacketNumber, retransmission.PacketNumber);
            Assert.True(testCase.PacketBytes.AsSpan().SequenceEqual(retransmission.PacketBytes.Span));
            testCase.VerifyPacketBytes(retransmission.PacketBytes.ToArray());
            Assert.False(runtime.TryDequeueRetransmission(out _));
        }

        QuicConnectionSendRuntime acknowledgedRuntime = new();
        byte[] acknowledgedPacket = QuicFrameTestData.BuildCryptoFrame(new QuicCryptoFrame(8, [0xB0, 0xB1]));
        acknowledgedRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.Handshake,
            PacketNumber: 20,
            PayloadBytes: (ulong)acknowledgedPacket.Length,
            SentAtMicros: 2_000,
            AckEliciting: true,
            Retransmittable: true,
            PacketBytes: acknowledgedPacket,
            CryptoMetadata: new QuicConnectionCryptoSendMetadata(QuicTlsEncryptionLevel.Handshake)));

        Assert.True(acknowledgedRuntime.TryRegisterLoss(
            QuicPacketNumberSpace.Handshake,
            20,
            handshakeConfirmed: true));
        Assert.True(acknowledgedRuntime.TryAcknowledgePacket(
            QuicPacketNumberSpace.Handshake,
            20,
            handshakeConfirmed: true));
        Assert.Equal(0, acknowledgedRuntime.PendingRetransmissionCount);
        Assert.False(acknowledgedRuntime.TryDequeueRetransmission(out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0797")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ConnectionCloseLossFuzz_DoesNotTrackCloseDatagramsForRetransmission()
    {
        foreach ((QuicTransportErrorCode ErrorCode, ulong TriggeringFrameType) testCase in new (QuicTransportErrorCode, ulong)[]
        {
            (QuicTransportErrorCode.NoError, 0x00UL),
            (QuicTransportErrorCode.ProtocolViolation, 0x1CUL),
            (QuicTransportErrorCode.FlowControlError, 0x10UL),
        })
        {
            QuicConnectionRuntime runtime = CreateRuntimeWithActivePath();
            int sentPacketCountBefore = runtime.SendRuntime.SentPackets.Count;
            int pendingRetransmissionCountBefore = runtime.SendRuntime.PendingRetransmissionCount;

            QuicConnectionTransitionResult result = runtime.Transition(
                new QuicConnectionLocalCloseRequestedEvent(
                    ObservedAtTicks: 1,
                    new QuicConnectionCloseMetadata(
                        testCase.ErrorCode,
                        ApplicationErrorCode: null,
                        testCase.TriggeringFrameType,
                        ReasonPhrase: null)),
                nowTicks: 1);

            QuicConnectionSendDatagramEffect send = Assert.IsType<QuicConnectionSendDatagramEffect>(
                Assert.Single(result.Effects, effect => effect is QuicConnectionSendDatagramEffect));
            Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(
                send.Datagram.Span,
                out QuicConnectionCloseFrame closeFrame,
                out int bytesConsumed));
            Assert.Equal(send.Datagram.Length, bytesConsumed);
            Assert.Equal((ulong)testCase.ErrorCode, closeFrame.ErrorCode);
            Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
            Assert.Equal(QuicConnectionSendingMode.CloseOnly, runtime.SendingMode);
            Assert.Equal(sentPacketCountBefore, runtime.SendRuntime.SentPackets.Count);
            Assert.Equal(pendingRetransmissionCountBefore, runtime.SendRuntime.PendingRetransmissionCount);
            Assert.False(runtime.SendRuntime.TryDequeueRetransmission(out _));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0818")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void CongestionLossFuzz_ReducesTheCongestionWindowForEligibleLossSignals()
    {
        foreach ((ulong SentBytes, ulong LostBytes, ulong SentAtMicros) testCase in new (ulong, ulong, ulong)[]
        {
            (12_000UL, 600UL, 2_000UL),
            (12_000UL, 1_200UL, 2_500UL),
            (12_000UL, 2_400UL, 3_000UL),
        })
        {
            QuicCongestionControlState state = new();
            state.RegisterPacketSent(testCase.SentBytes);

            Assert.True(state.TryRegisterLoss(
                testCase.LostBytes,
                testCase.SentAtMicros,
                packetInFlight: true));

            Assert.True(state.HasRecoveryStartTime);
            Assert.Equal(testCase.SentAtMicros, state.RecoveryStartTimeMicros);
            Assert.Equal(6_000UL, state.CongestionWindowBytes);
            Assert.Equal(6_000UL, state.SlowStartThresholdBytes);
            Assert.Equal(testCase.SentBytes - testCase.LostBytes, state.BytesInFlightBytes);
        }
    }

    private static QuicHandshakeFlowCoordinator CreateApplicationCoordinator()
    {
        QuicHandshakeFlowCoordinator coordinator = new(PacketConnectionId, PacketSourceConnectionId);
        Assert.True(coordinator.TrySetDestinationConnectionId(PacketConnectionId));
        return coordinator;
    }

    private static bool AckFrameCoversPacketNumber(QuicAckFrame frame, ulong packetNumber)
    {
        if (packetNumber > frame.LargestAcknowledged)
        {
            return false;
        }

        ulong largest = frame.LargestAcknowledged;
        ulong smallest = largest - frame.FirstAckRange;
        if (packetNumber >= smallest)
        {
            return true;
        }

        foreach (QuicAckRange range in frame.AdditionalRanges)
        {
            largest = smallest - range.Gap - 2;
            smallest = largest - range.AckRangeLength;
            if (packetNumber >= smallest && packetNumber <= largest)
            {
                return true;
            }
        }

        return false;
    }

    private static void VerifyCryptoFrame(byte[] packetBytes)
    {
        Assert.True(QuicFrameCodec.TryParseCryptoFrame(packetBytes, out QuicCryptoFrame frame, out int bytesConsumed));
        Assert.Equal(packetBytes.Length, bytesConsumed);
        Assert.NotEmpty(frame.CryptoData.ToArray());
    }

    private static void VerifyResetStreamFrame(byte[] packetBytes)
    {
        Assert.True(QuicFrameCodec.TryParseResetStreamFrame(packetBytes, out QuicResetStreamFrame frame, out int bytesConsumed));
        Assert.Equal(packetBytes.Length, bytesConsumed);
        Assert.Equal(1UL, frame.StreamId);
        Assert.Equal(0x99UL, frame.ApplicationProtocolErrorCode);
        Assert.Equal(4UL, frame.FinalSize);
    }

    private static void VerifyMaxDataFrame(byte[] packetBytes)
    {
        Assert.True(QuicFrameCodec.TryParseMaxDataFrame(packetBytes, out QuicMaxDataFrame frame, out int bytesConsumed));
        Assert.Equal(packetBytes.Length, bytesConsumed);
        Assert.Equal(128UL, frame.MaximumData);
    }

    private static QuicConnectionRuntime CreateRuntimeWithActivePath()
    {
        QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            new FakeMonotonicClock(0),
            currentProbeTimeoutMicros: 100);

        runtime.Transition(
            new QuicConnectionTransportParametersCommittedEvent(
                ObservedAtTicks: 0,
                TransportFlags: QuicConnectionTransportState.PeerTransportParametersCommitted,
                LocalMaxIdleTimeoutMicros: 200,
                PeerMaxIdleTimeoutMicros: 200,
                CurrentProbeTimeoutMicros: 100),
            nowTicks: 0);
        runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 0,
                new QuicConnectionPathIdentity("203.0.113.63", RemotePort: 443),
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 0);

        return runtime;
    }

    private sealed class FakeMonotonicClock : IMonotonicClock
    {
        public FakeMonotonicClock(long ticks)
        {
            Ticks = ticks;
        }

        public long Ticks { get; }

        public double Seconds => Ticks / (double)TimeSpan.TicksPerSecond;
    }
}
