namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9221-S3-0001")]
public sealed class REQ_QUIC_RFC9221_S3_0001_Focused
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientTransportParameters_AdvertiseMaxDatagramFrameSizeWhenConfigured()
    {
        QuicTransportParameters parameters = new()
        {
            MaxDatagramFrameSize = 1200,
        };
        Span<byte> destination = stackalloc byte[32];

        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            QuicTransportParameterRole.Client,
            destination,
            out int bytesWritten));

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            destination[..bytesWritten],
            QuicTransportParameterRole.Server,
            out QuicTransportParameters parsed));
        Assert.Equal(1200UL, parsed.MaxDatagramFrameSize);
    }
}

[Requirement("REQ-QUIC-RFC9221-S3-0002")]
public sealed class REQ_QUIC_RFC9221_S3_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DatagramFrameSize_IncludesFrameTypeLengthAndPayload()
    {
        QuicDatagramFrame frame = new()
        {
            FrameType = QuicFrameCodec.DatagramWithLengthFrameType,
            DatagramData = [0xA0, 0xA1],
        };

        byte[] encoded = QuicFrameTestData.BuildDatagramFrame(frame);

        Assert.Equal(4, encoded.Length);
        Assert.True(QuicFrameCodec.TryParseDatagramFrame(encoded, out _, out int completeFrameSize));
        Assert.Equal(encoded.Length, completeFrameSize);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void EmptyDatagramFrameSize_StillIncludesTypeAndLengthFieldWhenLengthBitIsSet()
    {
        byte[] encoded = QuicFrameTestData.BuildDatagramFrame(new QuicDatagramFrame
        {
            FrameType = QuicFrameCodec.DatagramWithLengthFrameType,
            DatagramData = [],
        });

        Assert.Equal(new byte[] { QuicFrameCodec.DatagramWithLengthFrameType, 0x00 }, encoded);
    }
}

[Requirement("REQ-QUIC-RFC9221-S3-0009")]
public sealed class REQ_QUIC_RFC9221_S3_0009_Focused
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RememberedZeroRttTransportParameters_KeepServerMaxDatagramFrameSize()
    {
        QuicTransportParameters remembered = Assert.IsType<QuicTransportParameters>(
            QuicZeroRttTransportParameterPolicy.CreateRememberedTransportParametersForClientZeroRtt(
                new QuicTransportParameters
                {
                    MaxDatagramFrameSize = 1200,
                }));

        Assert.Equal(1200UL, remembered.MaxDatagramFrameSize);
    }
}

[Requirement("REQ-QUIC-RFC9221-S3-0011")]
public sealed class REQ_QUIC_RFC9221_S3_0011
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task PublicSendApiReportsMissingPeerDatagramSupportToApplicationProtocol()
    {
        QuicConnectionRuntime runtime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
            localMaxDatagramFrameSize: 1200);

        InvalidOperationException exception = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await QuicDatagramRuntimeTestSupport.SendDatagramAsync(runtime, new byte[] { 0x01 }));

        Assert.Contains("did not advertise QUIC DATAGRAM support", exception.Message, StringComparison.Ordinal);
    }
}

[Requirement("REQ-QUIC-RFC9221-S3-0003")]
public sealed class REQ_QUIC_RFC9221_S3_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task MissingPeerDatagramParameter_IsTreatedAsSendUnsupported()
    {
        QuicConnectionRuntime runtime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
            localMaxDatagramFrameSize: 1200);

        await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await QuicDatagramRuntimeTestSupport.SendDatagramAsync(runtime, new byte[] { 0x01 }));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task MissingLocalDatagramParameter_IsTreatedAsReceiveUnsupported()
    {
        QuicConnectionRuntime runtime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
            peerMaxDatagramFrameSize: 1200);

        await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await runtime.ReceiveDatagramAsync());
    }
}

[Requirement("REQ-QUIC-RFC9221-S3-0008")]
public sealed class REQ_QUIC_RFC9221_S3_0008
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task LocalReceiveSupportAndPeerSendSupport_AreEvaluatedIndependently()
    {
        QuicConnectionRuntime runtime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
            localMaxDatagramFrameSize: 4,
            peerMaxDatagramFrameSize: 1200);

        QuicConnectionTransitionResult receiveResult = QuicDatagramRuntimeTestSupport.ReceiveProtectedDatagramFrame(
            runtime,
            new QuicDatagramFrame
            {
                FrameType = QuicFrameCodec.DatagramWithLengthFrameType,
                DatagramData = [0xA0, 0xA1],
            });
        QuicDatagramSendResult sendResult =
            await QuicDatagramRuntimeTestSupport.SendDatagramAsync(runtime, new byte[] { 0xB0, 0xB1, 0xB2 });

        Assert.Single(receiveResult.Effects.OfType<QuicConnectionDeliverDatagramEffect>());
        Assert.NotNull(sendResult.SendEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public async Task EndpointMaySendDatagramEvenWhenItDidNotAdvertiseReceiveSupport()
    {
        QuicConnectionRuntime runtime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
            peerMaxDatagramFrameSize: 1200);

        QuicDatagramSendResult sendResult =
            await QuicDatagramRuntimeTestSupport.SendDatagramAsync(runtime, new byte[] { 0xB0 });

        Assert.NotNull(sendResult.SendEffect);
    }
}

[Requirement("REQ-QUIC-RFC9221-S3-0010")]
public sealed class REQ_QUIC_RFC9221_S3_0010
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EvaluateServerZeroRttAcceptance_AcceptsEqualRememberedMaxDatagramFrameSize()
    {
        QuicZeroRttTransportParameterAcceptanceDecision decision =
            QuicZeroRttTransportParameterPolicy.EvaluateServerZeroRttAcceptance(
                CreateZeroRttParameters(1200),
                CreateZeroRttParameters(1200));

        Assert.True(decision.CanAccept);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void EvaluateServerZeroRttAcceptance_RejectsLowerMaxDatagramFrameSize()
    {
        QuicZeroRttTransportParameterAcceptanceDecision decision =
            QuicZeroRttTransportParameterPolicy.EvaluateServerZeroRttAcceptance(
                CreateZeroRttParameters(1200),
                CreateZeroRttParameters(1199));

        Assert.False(decision.CanAccept);
        Assert.Equal(QuicZeroRttTransportParameterAcceptanceFailure.ReducedOptionalValue, decision.Failure);
        Assert.Equal("max_datagram_frame_size", decision.ParameterName);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void EvaluateServerZeroRttAcceptance_AcceptsIncreasedMaxDatagramFrameSize()
    {
        QuicZeroRttTransportParameterAcceptanceDecision decision =
            QuicZeroRttTransportParameterPolicy.EvaluateServerZeroRttAcceptance(
                CreateZeroRttParameters(1200),
                CreateZeroRttParameters(1300));

        Assert.True(decision.CanAccept);
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
}

[Requirement("REQ-QUIC-RFC9221-S5-0002")]
public sealed class REQ_QUIC_RFC9221_S5_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ReceivedDatagram_IsDeliveredAsConnectionScopedDataWithoutStreamState()
    {
        using QuicConnectionRuntime runtime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
            localMaxDatagramFrameSize: 1200);

        QuicConnectionTransitionResult result = QuicDatagramRuntimeTestSupport.ReceiveProtectedDatagramFrame(
            runtime,
            new QuicDatagramFrame
            {
                FrameType = QuicFrameCodec.DatagramWithLengthFrameType,
                DatagramData = [0x51, 0x52],
            });

        QuicConnectionDeliverDatagramEffect deliver =
            Assert.Single(result.Effects.OfType<QuicConnectionDeliverDatagramEffect>());
        Assert.Equal([0x51, 0x52], deliver.Datagram.ToArray());
        Assert.False(runtime.StreamRegistry.Bookkeeping.TryGetStreamSnapshot(0, out _));
        Assert.False(runtime.StreamRegistry.Bookkeeping.TryGetStreamSnapshot(1, out _));
    }
}

[Requirement("REQ-QUIC-RFC9221-S5-0003")]
public sealed class REQ_QUIC_RFC9221_S5_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RuntimePreservesDatagramPayloadBytesWithoutInterpretingApplicationMultiplexing()
    {
        using QuicConnectionRuntime runtime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
            localMaxDatagramFrameSize: 1200);
        byte[] applicationPayload = [0x00, 0x01, 0xFE, 0xFF];

        QuicConnectionTransitionResult result = QuicDatagramRuntimeTestSupport.ReceiveProtectedDatagramFrame(
            runtime,
            new QuicDatagramFrame
            {
                FrameType = QuicFrameCodec.DatagramWithLengthFrameType,
                DatagramData = applicationPayload,
            });

        QuicConnectionDeliverDatagramEffect deliver =
            Assert.Single(result.Effects.OfType<QuicConnectionDeliverDatagramEffect>());
        Assert.Equal(applicationPayload, deliver.Datagram.ToArray());
    }
}

[Requirement("REQ-QUIC-RFC9221-S5-0004")]
public sealed class REQ_QUIC_RFC9221_S5_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ReceiverDropsDatagramWhenInboundQueueIsFullWithoutClosingConnection()
    {
        using QuicConnectionRuntime runtime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
            localMaxDatagramFrameSize: 1200,
            maximumInboundDatagramQueueSize: 1);

        QuicConnectionTransitionResult first = QuicDatagramRuntimeTestSupport.ReceiveProtectedDatagramFrame(
            runtime,
            new QuicDatagramFrame
            {
                FrameType = QuicFrameCodec.DatagramWithLengthFrameType,
                DatagramData = [0x01],
            });
        QuicConnectionTransitionResult second = QuicDatagramRuntimeTestSupport.ReceiveProtectedDatagramFrame(
            runtime,
            new QuicDatagramFrame
            {
                FrameType = QuicFrameCodec.DatagramWithLengthFrameType,
                DatagramData = [0x02],
            },
            observedAtTicks: 30);

        Assert.Single(first.Effects.OfType<QuicConnectionDeliverDatagramEffect>());
        Assert.DoesNotContain(second.Effects, effect => effect is QuicConnectionDeliverDatagramEffect);
        Assert.Null(runtime.TerminalState);
    }
}

[Requirement("REQ-QUIC-RFC9221-S5-0006")]
public sealed class REQ_QUIC_RFC9221_S5_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task SendDatagramAsync_CanCoalesceDatagramFrameWithPendingAck()
    {
        using QuicConnectionRuntime runtime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
            localMaxDatagramFrameSize: 1200,
            peerMaxDatagramFrameSize: 1200);
        _ = QuicDatagramRuntimeTestSupport.ReceiveProtectedDatagramFrame(
            runtime,
            new QuicDatagramFrame
            {
                FrameType = QuicFrameCodec.DatagramWithLengthFrameType,
                DatagramData = [0xA0],
            });

        QuicDatagramSendResult sendResult =
            await QuicDatagramRuntimeTestSupport.SendDatagramAsync(runtime, new byte[] { 0xB0 });

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
        Assert.True(QuicFrameCodec.TryParseDatagramFrame(remaining, out QuicDatagramFrame datagramFrame, out _));
        Assert.Equal([0xB0], datagramFrame.DatagramData);
    }
}

[Requirement("REQ-QUIC-RFC9221-S5P2-0003")]
public sealed class REQ_QUIC_RFC9221_S5P2_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DatagramOnlyPacket_ArmsDelayedAckInsteadOfImmediateAckWhenWithinMaxAckDelay()
    {
        FakeMonotonicClock clock = new(0);
        using QuicConnectionRuntime runtime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
            clock: clock,
            localMaxDatagramFrameSize: 1200);

        QuicConnectionTransitionResult result = QuicDatagramRuntimeTestSupport.ReceiveProtectedDatagramFrame(
            runtime,
            new QuicDatagramFrame
            {
                FrameType = QuicFrameCodec.DatagramWithLengthFrameType,
                DatagramData = [0xA0],
            });

        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionSendDatagramEffect);
        Assert.Contains(result.Effects, effect => effect is QuicConnectionArmTimerEffect
        {
            TimerKind: QuicConnectionTimerKind.AckDelay
        });
    }
}

[Requirement("REQ-QUIC-RFC9221-S5P2-0004")]
public sealed class REQ_QUIC_RFC9221_S5P2_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task DatagramAckNotification_DoesNotReportApplicationProcessing()
    {
        using QuicConnectionRuntime runtime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
            localMaxDatagramFrameSize: 1200,
            peerMaxDatagramFrameSize: 1200);

        QuicDatagramSendResult sendResult =
            await QuicDatagramRuntimeTestSupport.SendDatagramAsync(runtime, new byte[] { 0xA0 });
        Assert.NotNull(sendResult.TrackedPacket);

        bool acknowledged = runtime.SendRuntime.TryAcknowledgePacket(
            QuicPacketNumberSpace.ApplicationData,
            sendResult.TrackedPacket.Value.PacketNumber);

        Assert.True(acknowledged);
        Assert.False(sendResult.TrackedPacket.Value.Retransmittable);
        Assert.Null(sendResult.TrackedPacket.Value.StreamIds);
        Assert.DoesNotContain(sendResult.Effects, effect => effect is QuicConnectionDeliverDatagramEffect);
    }
}

[Requirement("REQ-QUIC-RFC9221-S6-0002")]
public sealed class REQ_QUIC_RFC9221_S6_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task SendDatagramAsync_UsesOneRttPathAndDoesNotEnableZeroRttDatagramWithoutApplicationProfile()
    {
        using QuicConnectionRuntime runtime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
            localMaxDatagramFrameSize: 1200,
            peerMaxDatagramFrameSize: 1200);

        QuicDatagramSendResult sendResult =
            await QuicDatagramRuntimeTestSupport.SendDatagramAsync(runtime, new byte[] { 0xA0 });

        Assert.NotNull(sendResult.TrackedPacket);
        Assert.Equal(QuicTlsEncryptionLevel.OneRtt, sendResult.TrackedPacket.Value.PacketProtectionLevel);
    }
}
