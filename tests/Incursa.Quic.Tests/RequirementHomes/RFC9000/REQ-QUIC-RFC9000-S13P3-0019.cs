namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P3-0019">An endpoint SHOULD stop sending MAX_STREAM_DATA frames when the receiving part of the stream enters a Size Known or Reset Recvd state.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P3-0019")]
public sealed class REQ_QUIC_RFC9000_S13P3_0019
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0019")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReadStreamData_StopsAdvertisingStreamCreditOnceTheStreamIsClosedOrReset()
    {
        QuicConnectionStreamState closedState = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 32,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0F, 1, [0x11, 0x22, 0x33, 0x44], offset: 0),
            out QuicStreamFrame finFrame));
        Assert.True(closedState.TryReceiveStreamFrame(finFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Span<byte> destination = stackalloc byte[4];
        Assert.True(closedState.TryReadStreamData(
            1,
            destination,
            out int bytesWritten,
            out bool completed,
            out QuicMaxDataFrame maxDataFrame,
            out QuicMaxStreamDataFrame maxStreamDataFrame,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(4, bytesWritten);
        Assert.True(completed);
        Assert.Equal(12UL, maxStreamDataFrame.MaximumStreamData);

        Assert.True(closedState.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot closedSnapshot));
        Assert.Equal(QuicStreamReceiveState.DataRead, closedSnapshot.ReceiveState);

        Assert.False(closedState.TryReadStreamData(
            1,
            destination,
            out bytesWritten,
            out completed,
            out maxDataFrame,
            out maxStreamDataFrame,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(0, bytesWritten);
        Assert.True(completed);
        Assert.Equal(default, maxDataFrame);
        Assert.Equal(default, maxStreamDataFrame);

        QuicConnectionStreamState resetState = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: QuicVariableLengthInteger.MaxValue,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, 1, [0x55, 0x66], offset: 0),
            out QuicStreamFrame resetFrame));
        Assert.True(resetState.TryReceiveStreamFrame(resetFrame, out errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(resetState.TryReceiveResetStreamFrame(
            new QuicResetStreamFrame(streamId: 1, applicationProtocolErrorCode: 0x99, finalSize: 5),
            out _,
            out errorCode));

        Assert.Equal(default, errorCode);

        Assert.False(resetState.TryReadStreamData(
            1,
            destination,
            out bytesWritten,
            out completed,
            out maxDataFrame,
            out maxStreamDataFrame,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(0, bytesWritten);
        Assert.False(completed);
        Assert.Equal(default, maxDataFrame);
        Assert.Equal(default, maxStreamDataFrame);

        Assert.True(resetState.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot resetSnapshot));
        Assert.Equal(QuicStreamReceiveState.ResetRecvd, resetSnapshot.ReceiveState);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0019")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task ReadAsync_DoesNotEmitAdditionalMaxStreamDataAfterTheStreamHasReachedItsFinalSize()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        List<QuicConnectionEffect> outboundEffects = [];
        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        AcknowledgeTrackedPackets(runtime);

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        AcknowledgeTrackedPackets(runtime);
        outboundEffects.Clear();

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0F, (ulong)stream.Id, [0x11, 0x22], offset: 0),
            out QuicStreamFrame streamFrame));
        Assert.True(runtime.StreamRegistry.Bookkeeping.TryReceiveStreamFrame(streamFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        byte[] readBuffer = new byte[2];
        int bytesRead = await stream.ReadAsync(readBuffer, 0, readBuffer.Length);

        Assert.Equal(2, bytesRead);
        Assert.True(runtime.StreamRegistry.Bookkeeping.TryGetStreamSnapshot((ulong)stream.Id, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamReceiveState.DataRead, snapshot.ReceiveState);
        Assert.NotEmpty(outboundEffects);
        outboundEffects.Clear();

        bytesRead = await stream.ReadAsync(readBuffer, 0, readBuffer.Length);

        Assert.Equal(0, bytesRead);

        bool sawMaxStreamData = false;
        QuicHandshakeFlowCoordinator coordinator = new(new byte[] { 0x0A, 0x0B, 0x0C });
        foreach (QuicConnectionEffect effect in outboundEffects)
        {
            if (effect is not QuicConnectionSendDatagramEffect sendEffect)
            {
                continue;
            }

            Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
                sendEffect.Datagram.Span,
                runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
                out byte[] openedPacket,
                out int payloadOffset,
                out int payloadLength));

            if (QuicFrameCodec.TryParseMaxStreamDataFrame(
                openedPacket.AsSpan(payloadOffset, payloadLength),
                out _,
                out _))
            {
                sawMaxStreamData = true;
            }
        }

        Assert.False(sawMaxStreamData);
    }

    private static void AcknowledgeTrackedPackets(QuicConnectionRuntime runtime)
    {
        foreach (KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> sentPacket in runtime.SendRuntime.SentPackets.ToArray())
        {
            Assert.True(runtime.SendRuntime.TryAcknowledgePacket(
                sentPacket.Key.PacketNumberSpace,
                sentPacket.Key.PacketNumber,
                handshakeConfirmed: true));
        }
    }
}
