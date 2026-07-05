// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9221_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9221-S3-0001")]
    [Requirement("REQ-QUIC-RFC9221-S3-0002")]
    [Requirement("REQ-QUIC-RFC9221-S3-0003")]
    [Requirement("REQ-QUIC-RFC9221-S3-0008")]
    [Requirement("REQ-QUIC-RFC9221-S3-0009")]
    [Requirement("REQ-QUIC-RFC9221-S3-0010")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_MaxDatagramFrameSizeTransportParameter_RoundTripsAndPreservesZeroRttPolicy()
    {
        byte[] destination = new byte[32];
        foreach (ulong maxDatagramFrameSize in new ulong[] { 1, 2, 3, 4, 63, 64, 1_200, 65_535, 1_048_576 })
        {
            QuicTransportParameters parameters = new()
            {
                MaxDatagramFrameSize = maxDatagramFrameSize,
            };

            Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
                parameters,
                QuicTransportParameterRole.Client,
                destination,
                out int bytesWritten));
            Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
                destination[..bytesWritten],
                QuicTransportParameterRole.Server,
                out QuicTransportParameters parsed));
            Assert.Equal(maxDatagramFrameSize, parsed.MaxDatagramFrameSize);

            QuicTransportParameters remembered =
                Assert.IsType<QuicTransportParameters>(
                    QuicZeroRttTransportParameterPolicy.CreateRememberedTransportParametersForClientZeroRtt(parameters));
            Assert.Equal(maxDatagramFrameSize, remembered.MaxDatagramFrameSize);

            Assert.True(QuicZeroRttTransportParameterPolicy
                .EvaluateServerZeroRttAcceptance(remembered, CreateZeroRttParameters(maxDatagramFrameSize))
                .CanAccept);
            Assert.True(QuicZeroRttTransportParameterPolicy
                .EvaluateServerZeroRttAcceptance(remembered, CreateZeroRttParameters(maxDatagramFrameSize + 1))
                .CanAccept);

            if (maxDatagramFrameSize > 1)
            {
                QuicZeroRttTransportParameterAcceptanceDecision reduced =
                    QuicZeroRttTransportParameterPolicy.EvaluateServerZeroRttAcceptance(
                        remembered,
                        CreateZeroRttParameters(maxDatagramFrameSize - 1));

                Assert.False(reduced.CanAccept);
                Assert.Equal(QuicZeroRttTransportParameterAcceptanceFailure.ReducedOptionalValue, reduced.Failure);
                Assert.Equal("max_datagram_frame_size", reduced.ParameterName);
            }
        }

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            [],
            QuicTransportParameterRole.Server,
            out QuicTransportParameters absent));
        Assert.Null(absent.MaxDatagramFrameSize);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9221-S3-0004")]
    [Requirement("REQ-QUIC-RFC9221-S3-0005")]
    [Requirement("REQ-QUIC-RFC9221-S3-0006")]
    [Requirement("REQ-QUIC-RFC9221-S3-0007")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public async Task Fuzz_DatagramNegotiationAndSizeLimits_RejectUnsupportedOrOversizedFrames()
    {
        foreach (int peerLimit in new[] { 2, 3, 4, 8, 63 })
        {
            using QuicConnectionRuntime sendRuntime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
                localMaxDatagramFrameSize: 1_200,
                peerMaxDatagramFrameSize: (ulong)peerLimit);
            byte[] allowedPayload = RandomBytes(peerLimit - 2);
            QuicDatagramSendResult allowed = await QuicDatagramRuntimeTestSupport.SendDatagramAsync(
                sendRuntime,
                allowedPayload);
            Assert.NotNull(allowed.SendEffect);

            using QuicConnectionRuntime oversizeSendRuntime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
                localMaxDatagramFrameSize: 1_200,
                peerMaxDatagramFrameSize: (ulong)peerLimit);
            await Assert.ThrowsAsync<InvalidOperationException>(
                async () => await QuicDatagramRuntimeTestSupport.SendDatagramAsync(
                    oversizeSendRuntime,
                    RandomBytes(peerLimit - 1)));
            Assert.Null(oversizeSendRuntime.TerminalState);

            using QuicConnectionRuntime receiveRuntime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
                localMaxDatagramFrameSize: (ulong)peerLimit);
            QuicConnectionTransitionResult receiveResult = QuicDatagramRuntimeTestSupport.ReceiveProtectedDatagramFrame(
                receiveRuntime,
                new QuicDatagramFrame
                {
                    FrameType = QuicFrameCodec.DatagramWithLengthFrameType,
                    DatagramData = allowedPayload,
                });
            Assert.Single(receiveResult.Effects.OfType<QuicConnectionDeliverDatagramEffect>());

            using QuicConnectionRuntime oversizeReceiveRuntime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
                localMaxDatagramFrameSize: (ulong)peerLimit);
            _ = QuicDatagramRuntimeTestSupport.ReceiveProtectedDatagramFrame(
                oversizeReceiveRuntime,
                new QuicDatagramFrame
                {
                    FrameType = QuicFrameCodec.DatagramWithLengthFrameType,
                    DatagramData = RandomBytes(peerLimit - 1),
                });
            AssertProtocolViolation(oversizeReceiveRuntime);
        }

        using QuicConnectionRuntime unsupportedSendRuntime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
            localMaxDatagramFrameSize: 1_200);
        await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await QuicDatagramRuntimeTestSupport.SendDatagramAsync(unsupportedSendRuntime, new byte[] { 0xD1 }));

        using QuicConnectionRuntime unsupportedReceiveRuntime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime();
        _ = QuicDatagramRuntimeTestSupport.ReceiveProtectedDatagramFrame(
            unsupportedReceiveRuntime,
            new QuicDatagramFrame
            {
                FrameType = QuicFrameCodec.DatagramWithLengthFrameType,
                DatagramData = new byte[] { 0xD1 },
            });
        AssertProtocolViolation(unsupportedReceiveRuntime);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9221-S5-0001")]
    [Requirement("REQ-QUIC-RFC9221-S5-0002")]
    [Requirement("REQ-QUIC-RFC9221-S5-0004")]
    [Requirement("REQ-QUIC-RFC9221-S5-0005")]
    [Requirement("REQ-QUIC-RFC9221-S5-0006")]
    [Requirement("REQ-QUIC-RFC9221-S5-0007")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public async Task Fuzz_DatagramPayloadDeliverySendingCoalescingAndNonFragmentation()
    {
        foreach (byte[] payload in new[]
                 {
                     Array.Empty<byte>(),
                     new byte[] { 0x01 },
                     RandomBytes(8),
                     RandomBytes(32),
                 })
        {
            using QuicConnectionRuntime receiveRuntime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
                localMaxDatagramFrameSize: 1_200);
            QuicConnectionTransitionResult result = QuicDatagramRuntimeTestSupport.ReceiveProtectedDatagramFrame(
                receiveRuntime,
                new QuicDatagramFrame
                {
                    FrameType = QuicFrameCodec.DatagramWithLengthFrameType,
                    DatagramData = payload,
                });

            QuicConnectionDeliverDatagramEffect delivered =
                Assert.Single(result.Effects.OfType<QuicConnectionDeliverDatagramEffect>());
            Assert.True(payload.AsSpan().SequenceEqual(delivered.Datagram.Span));
            Assert.False(receiveRuntime.StreamRegistry.Bookkeeping.TryGetStreamSnapshot(0, out _));

            using QuicConnectionRuntime sendRuntime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
                localMaxDatagramFrameSize: 1_200,
                peerMaxDatagramFrameSize: 1_200);
            QuicDatagramSendResult sendResult =
                await QuicDatagramRuntimeTestSupport.SendDatagramAsync(sendRuntime, payload);
            Assert.NotNull(sendResult.SendEffect);
            QuicDatagramFrame frame = QuicDatagramRuntimeTestSupport.ParseFirstOutgoingDatagramFrame(
                sendRuntime,
                sendResult.SendEffect);
            Assert.True(payload.AsSpan().SequenceEqual(frame.DatagramData.Span));

            using QuicConnectionRuntime queueLimitedRuntime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
                localMaxDatagramFrameSize: 1_200,
                maximumInboundDatagramQueueSize: 0);
            QuicConnectionTransitionResult dropped = QuicDatagramRuntimeTestSupport.ReceiveProtectedDatagramFrame(
                queueLimitedRuntime,
                new QuicDatagramFrame
                {
                    FrameType = QuicFrameCodec.DatagramWithLengthFrameType,
                    DatagramData = payload,
                });
            Assert.DoesNotContain(dropped.Effects, effect => effect is QuicConnectionDeliverDatagramEffect);
            Assert.Null(queueLimitedRuntime.TerminalState);
        }

        using QuicConnectionRuntime coalescingRuntime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
            localMaxDatagramFrameSize: 1_200,
            peerMaxDatagramFrameSize: 1_200);
        _ = QuicDatagramRuntimeTestSupport.ReceiveProtectedDatagramFrame(
            coalescingRuntime,
            new QuicDatagramFrame
            {
                FrameType = QuicFrameCodec.DatagramWithLengthFrameType,
                DatagramData = new byte[] { 0xAA },
            });
        QuicDatagramSendResult coalesced =
            await QuicDatagramRuntimeTestSupport.SendDatagramAsync(coalescingRuntime, new byte[] { 0xBB });
        Assert.NotNull(coalesced.SendEffect);
        byte[] applicationPayload = QuicS13AckPiggybackTestSupport.OpenOutgoingApplicationPayload(
            coalescingRuntime,
            coalesced.SendEffect);
        ReadOnlySpan<byte> remaining = applicationPayload;
        while (!remaining.IsEmpty && remaining[0] == 0)
        {
            remaining = remaining[1..];
        }

        Assert.True(QuicFrameCodec.TryParseAckFrame(
            remaining,
            out _,
            out int ackBytesConsumed));
        Assert.True(ackBytesConsumed > 0);
        remaining = QuicDatagramRuntimeTestSupport.SkipAckAndPaddingFromPayload(remaining[ackBytesConsumed..]);
        Assert.True(QuicFrameCodec.TryParseDatagramFrame(remaining.ToArray(), out QuicDatagramFrame piggybacked, out _));
        Assert.Equal(new byte[] { 0xBB }, piggybacked.DatagramData.ToArray());

        using QuicConnectionRuntime fragmentRuntime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
            localMaxDatagramFrameSize: 1_200,
            peerMaxDatagramFrameSize: 4);
        await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await QuicDatagramRuntimeTestSupport.SendDatagramAsync(fragmentRuntime, RandomBytes(3)));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9221-S5P2-0002")]
    [Requirement("REQ-QUIC-RFC9221-S5P3-0001")]
    [Requirement("REQ-QUIC-RFC9221-S6-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public async Task Fuzz_DatagramLossFlowControlAndProtectionBoundaries()
    {
        foreach (byte[] payload in new[] { new byte[] { 0xD1 }, RandomBytes(17), RandomBytes(31) })
        {
            using QuicConnectionRuntime runtime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
                localMaxDatagramFrameSize: 1_200,
                peerMaxDatagramFrameSize: 1_200,
                connectionSendLimit: 1,
                localBidirectionalSendLimit: 0);

            QuicDatagramSendResult result = await QuicDatagramRuntimeTestSupport.SendDatagramAsync(runtime, payload);

            Assert.NotNull(result.SendEffect);
            Assert.NotNull(result.TrackedPacket);
            Assert.Equal(QuicTlsEncryptionLevel.OneRtt, result.TrackedPacket.Value.PacketProtectionLevel);
            Assert.Null(result.TrackedPacket.Value.StreamIds);
            Assert.Null(runtime.TerminalState);

            Assert.True(runtime.SendRuntime.TryRegisterLoss(
                result.TrackedPacket.Value.PacketNumberSpace,
                result.TrackedPacket.Value.PacketNumber,
                handshakeConfirmed: true));
            Assert.False(runtime.SendRuntime.TryDequeueRetransmission(out _));
        }

        Assert.True(QuicPacketFrameLegality.IsHandshakePacketForbiddenFrameType(
            QuicPacketFrameLegality.DatagramWithoutLengthFrameType));
        Assert.True(QuicPacketFrameLegality.IsHandshakePacketForbiddenFrameType(
            QuicPacketFrameLegality.DatagramWithLengthFrameType));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9221-S3-0011")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task MissingPeerDatagramSupport_IsReportedToTheApplicationProtocol()
    {
        using QuicConnectionRuntime runtime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
            localMaxDatagramFrameSize: 1_200);

        InvalidOperationException exception = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await QuicDatagramRuntimeTestSupport.SendDatagramAsync(runtime, new byte[] { 0x01 }));

        Assert.Contains("did not advertise QUIC DATAGRAM support", exception.Message, StringComparison.Ordinal);
        Assert.Null(runtime.TerminalState);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9221-S3-0011")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public async Task MissingLocalDatagramSupport_IsReportedToTheApplicationProtocol()
    {
        using QuicConnectionRuntime runtime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
            peerMaxDatagramFrameSize: 1_200);

        InvalidOperationException exception = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await runtime.ReceiveDatagramAsync());

        Assert.Contains("Local QUIC DATAGRAM receive support", exception.Message, StringComparison.Ordinal);
        Assert.Null(runtime.TerminalState);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9221-S5-0003")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ReceivedDatagramPayload_IsNotInterpretedAsTransportMultiplexingMetadata()
    {
        using QuicConnectionRuntime runtime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
            localMaxDatagramFrameSize: 1_200);
        byte[] applicationPayload = [0x00, 0x30, 0x31, 0xFF];

        QuicConnectionTransitionResult result = QuicDatagramRuntimeTestSupport.ReceiveProtectedDatagramFrame(
            runtime,
            new QuicDatagramFrame
            {
                FrameType = QuicFrameCodec.DatagramWithLengthFrameType,
                DatagramData = applicationPayload,
            });

        QuicConnectionDeliverDatagramEffect delivered =
            Assert.Single(result.Effects.OfType<QuicConnectionDeliverDatagramEffect>());
        Assert.True(applicationPayload.AsSpan().SequenceEqual(delivered.Datagram.Span));
        Assert.False(runtime.StreamRegistry.Bookkeeping.TryGetStreamSnapshot(0, out _));
        Assert.Null(runtime.TerminalState);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9221-S5-0003")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void EmptyDatagramPayload_IsStillDeliveredWithoutTransportInterpretation()
    {
        using QuicConnectionRuntime runtime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
            localMaxDatagramFrameSize: 1_200);

        QuicConnectionTransitionResult result = QuicDatagramRuntimeTestSupport.ReceiveProtectedDatagramFrame(
            runtime,
            new QuicDatagramFrame
            {
                FrameType = QuicFrameCodec.DatagramWithLengthFrameType,
                DatagramData = Array.Empty<byte>(),
            });

        QuicConnectionDeliverDatagramEffect delivered =
            Assert.Single(result.Effects.OfType<QuicConnectionDeliverDatagramEffect>());
        Assert.Empty(delivered.Datagram.ToArray());
        Assert.Null(runtime.TerminalState);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9221-S5-0004")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ReceiverWithDatagramQueueCapacity_StoresReceivedDatagram()
    {
        using QuicConnectionRuntime runtime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
            localMaxDatagramFrameSize: 1_200,
            maximumInboundDatagramQueueSize: 1);

        QuicConnectionTransitionResult result = QuicDatagramRuntimeTestSupport.ReceiveProtectedDatagramFrame(
            runtime,
            new QuicDatagramFrame
            {
                FrameType = QuicFrameCodec.DatagramWithLengthFrameType,
                DatagramData = new byte[] { 0x42 },
            });

        Assert.Single(result.Effects.OfType<QuicConnectionDeliverDatagramEffect>());
        Assert.Null(runtime.TerminalState);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9221-S5-0004")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ReceiverWithFullDatagramQueue_DropsWithoutClosingConnection()
    {
        using QuicConnectionRuntime runtime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
            localMaxDatagramFrameSize: 1_200,
            maximumInboundDatagramQueueSize: 0);

        QuicConnectionTransitionResult result = QuicDatagramRuntimeTestSupport.ReceiveProtectedDatagramFrame(
            runtime,
            new QuicDatagramFrame
            {
                FrameType = QuicFrameCodec.DatagramWithLengthFrameType,
                DatagramData = new byte[] { 0x42 },
            });

        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionDeliverDatagramEffect);
        Assert.Null(runtime.TerminalState);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9221-S5-0006")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public async Task EmptyDatagramCanBeCoalescedWithPendingAck()
    {
        using QuicConnectionRuntime runtime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
            localMaxDatagramFrameSize: 1_200,
            peerMaxDatagramFrameSize: 1_200);
        _ = QuicDatagramRuntimeTestSupport.ReceiveProtectedDatagramFrame(
            runtime,
            new QuicDatagramFrame
            {
                FrameType = QuicFrameCodec.DatagramWithLengthFrameType,
                DatagramData = new byte[] { 0xA0 },
            });

        QuicDatagramSendResult sendResult =
            await QuicDatagramRuntimeTestSupport.SendDatagramAsync(runtime, Array.Empty<byte>());

        Assert.NotNull(sendResult.SendEffect);
        byte[] payload = QuicS13AckPiggybackTestSupport.OpenOutgoingApplicationPayload(
            runtime,
            sendResult.SendEffect);
        ReadOnlySpan<byte> remaining = payload;
        while (!remaining.IsEmpty && remaining[0] == 0)
        {
            remaining = remaining[1..];
        }

        Assert.True(QuicFrameCodec.TryParseAckFrame(remaining, out _, out int ackBytesConsumed));
        remaining = QuicDatagramRuntimeTestSupport.SkipAckAndPaddingFromPayload(remaining[ackBytesConsumed..]);
        Assert.True(QuicFrameCodec.TryParseDatagramFrame(remaining.ToArray(), out QuicDatagramFrame frame, out _));
        Assert.Empty(frame.DatagramData.ToArray());
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9221-S5P2-0003")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DatagramOnlyPacket_DoesNotForceImmediateAck()
    {
        FakeMonotonicClock clock = new(0);
        using QuicConnectionRuntime runtime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
            clock: clock,
            localMaxDatagramFrameSize: 1_200);

        QuicConnectionTransitionResult result = QuicDatagramRuntimeTestSupport.ReceiveProtectedDatagramFrame(
            runtime,
            new QuicDatagramFrame
            {
                FrameType = QuicFrameCodec.DatagramWithLengthFrameType,
                DatagramData = new byte[] { 0xA0 },
            });

        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionSendDatagramEffect);
        Assert.Contains(result.Effects, effect => effect is QuicConnectionArmTimerEffect
        {
            TimerKind: QuicConnectionTimerKind.AckDelay
        });
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9221-S5P2-0003")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void EmptyDatagramOnlyPacket_StillUsesDelayedAckTimer()
    {
        FakeMonotonicClock clock = new(0);
        using QuicConnectionRuntime runtime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
            clock: clock,
            localMaxDatagramFrameSize: 1_200);

        QuicConnectionTransitionResult result = QuicDatagramRuntimeTestSupport.ReceiveProtectedDatagramFrame(
            runtime,
            new QuicDatagramFrame
            {
                FrameType = QuicFrameCodec.DatagramWithLengthFrameType,
                DatagramData = Array.Empty<byte>(),
            });

        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionSendDatagramEffect);
        Assert.Contains(result.Effects, effect => effect is QuicConnectionArmTimerEffect
        {
            TimerKind: QuicConnectionTimerKind.AckDelay
        });
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9221-S5P2-0004")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task DatagramPacketAcknowledgment_RemovesTransportTrackingOnly()
    {
        using QuicConnectionRuntime runtime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
            localMaxDatagramFrameSize: 1_200,
            peerMaxDatagramFrameSize: 1_200);

        QuicDatagramSendResult result =
            await QuicDatagramRuntimeTestSupport.SendDatagramAsync(runtime, new byte[] { 0xA0 });

        Assert.NotNull(result.TrackedPacket);
        Assert.True(runtime.SendRuntime.TryAcknowledgePacket(
            result.TrackedPacket.Value.PacketNumberSpace,
            result.TrackedPacket.Value.PacketNumber,
            handshakeConfirmed: true));
        Assert.False(result.TrackedPacket.Value.Retransmittable);
        Assert.Null(result.TrackedPacket.Value.StreamIds);
        Assert.False(runtime.SendRuntime.TryDequeueRetransmission(out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9221-S5P2-0004")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public async Task DuplicateDatagramPacketAcknowledgment_DoesNotCreateApplicationProcessingSignal()
    {
        using QuicConnectionRuntime runtime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
            localMaxDatagramFrameSize: 1_200,
            peerMaxDatagramFrameSize: 1_200);

        QuicDatagramSendResult result =
            await QuicDatagramRuntimeTestSupport.SendDatagramAsync(runtime, new byte[] { 0xA0 });

        Assert.NotNull(result.TrackedPacket);
        Assert.True(runtime.SendRuntime.TryAcknowledgePacket(
            result.TrackedPacket.Value.PacketNumberSpace,
            result.TrackedPacket.Value.PacketNumber,
            handshakeConfirmed: true));
        Assert.False(runtime.SendRuntime.TryAcknowledgePacket(
            result.TrackedPacket.Value.PacketNumberSpace,
            result.TrackedPacket.Value.PacketNumber,
            handshakeConfirmed: true));
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionDeliverDatagramEffect);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9221-S6-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task DatagramSendUsesOneRttWhenNoApplicationZeroRttProfileIsDefined()
    {
        using QuicConnectionRuntime runtime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
            localMaxDatagramFrameSize: 1_200,
            peerMaxDatagramFrameSize: 1_200);

        QuicDatagramSendResult result =
            await QuicDatagramRuntimeTestSupport.SendDatagramAsync(runtime, new byte[] { 0xA0 });

        Assert.NotNull(result.TrackedPacket);
        Assert.Equal(QuicTlsEncryptionLevel.OneRtt, result.TrackedPacket.Value.PacketProtectionLevel);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9221-S6-0002")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public async Task EmptyDatagramSendStillUsesOneRttWhenNoApplicationZeroRttProfileIsDefined()
    {
        using QuicConnectionRuntime runtime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
            localMaxDatagramFrameSize: 1_200,
            peerMaxDatagramFrameSize: 1_200);

        QuicDatagramSendResult result =
            await QuicDatagramRuntimeTestSupport.SendDatagramAsync(runtime, Array.Empty<byte>());

        Assert.NotNull(result.TrackedPacket);
        Assert.Equal(QuicTlsEncryptionLevel.OneRtt, result.TrackedPacket.Value.PacketProtectionLevel);
    }

    private static QuicTransportParameters CreateZeroRttParameters(ulong maxDatagramFrameSize)
    {
        return new QuicTransportParameters
        {
            ActiveConnectionIdLimit = 2,
            InitialMaxData = 1,
            InitialMaxStreamDataBidiLocal = 1,
            InitialMaxStreamDataBidiRemote = 1,
            InitialMaxStreamDataUni = 1,
            InitialMaxStreamsBidi = 1,
            InitialMaxStreamsUni = 1,
            MaxDatagramFrameSize = maxDatagramFrameSize,
        };
    }

    private static byte[] RandomBytes(int length)
    {
        byte[] bytes = new byte[length];
        Random random = new(0x5150_9221 + length);
        random.NextBytes(bytes);
        return bytes;
    }

    private static void AssertProtocolViolation(QuicConnectionRuntime runtime)
    {
        QuicConnectionTerminalState terminalState = Assert.IsType<QuicConnectionTerminalState>(runtime.TerminalState);
        Assert.Equal(QuicTransportErrorCode.ProtocolViolation, terminalState.Close.TransportErrorCode);
    }
}
