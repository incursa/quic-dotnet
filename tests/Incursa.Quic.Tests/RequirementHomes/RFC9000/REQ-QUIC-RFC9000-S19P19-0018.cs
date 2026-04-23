namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P19-0018">The application-specific variant of CONNECTION_CLOSE (type 0x1d) MAY only be sent using 0-RTT or 1-RTT packets; see Section 12.5.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S19P19-0018")]
public sealed class REQ_QUIC_RFC9000_S19P19_0018
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryGetPacketNumberSpace_MapsApplicationConnectionCloseFramesToApplicationData()
    {
        QuicConnectionCloseFrame applicationFrame = new(0x1234, reasonPhrase: []);
        byte[] payload = QuicFrameTestData.BuildConnectionCloseFrame(applicationFrame);
        byte[] applicationPacket = QuicHeaderTestData.BuildShortHeader(0x00, payload);

        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(applicationPacket, out QuicPacketNumberSpace packetNumberSpace));
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, packetNumberSpace);
        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(payload, out QuicConnectionCloseFrame parsedFrame, out int bytesConsumed));
        Assert.True(parsedFrame.IsApplicationError);
        Assert.Equal(payload.Length, bytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryGetPacketNumberSpace_DoesNotReclassifyHandshakePacketsAsApplicationDataWhenTheyCarryApplicationClosePayload()
    {
        QuicConnectionCloseFrame applicationFrame = new(0x1234, reasonPhrase: []);
        byte[] payload = QuicFrameTestData.BuildConnectionCloseFrame(applicationFrame);
        byte[] handshakePacket = QuicHandshakePacketRequirementTestData.BuildHandshakePacket(protectedPayload: payload);

        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(handshakePacket, out QuicPacketNumberSpace packetNumberSpace));
        Assert.Equal(QuicPacketNumberSpace.Handshake, packetNumberSpace);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void LocalCloseAfterOneRttKeysProtectsApplicationConnectionClosePacket()
    {
        // Regression provenance: artifacts\interop-runner\20260422-193035224-server-nginx showed
        // server CloseAsync(0) emitting 3-byte cleartext application CONNECTION_CLOSE payloads
        // after the managed response; quic-go ignored those bytes and timed out.
        (QuicConnectionRuntime runtime, QuicConnectionSendDatagramEffect send) = CreateOneRttApplicationCloseSend();

        QuicHandshakeFlowCoordinator coordinator = new(runtime.CurrentPeerDestinationConnectionId);
        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            send.Datagram.Span,
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength,
            out bool keyPhase));
        Assert.False(keyPhase);

        ReadOnlySpan<byte> payload = openedPacket.AsSpan(payloadOffset, payloadLength);
        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(payload, out QuicConnectionCloseFrame parsedFrame, out int bytesConsumed));
        Assert.True(parsedFrame.IsApplicationError);
        Assert.Equal(0UL, parsedFrame.ErrorCode);
        Assert.True(payload[bytesConsumed..].SequenceEqual(new byte[payloadLength - bytesConsumed]));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void LocalCloseAfterOneRttKeysDoesNotEmitBareApplicationClosePayload()
    {
        (_, QuicConnectionSendDatagramEffect send) = CreateOneRttApplicationCloseSend();

        QuicConnectionCloseFrame applicationFrame = new(0, reasonPhrase: []);
        byte[] barePayload = QuicFrameTestData.BuildConnectionCloseFrame(applicationFrame);

        Assert.NotEqual(barePayload.Length, send.Datagram.Length);
        Assert.False(barePayload.AsSpan().SequenceEqual(send.Datagram.Span));
        Assert.False(
            QuicFrameCodec.TryParseConnectionCloseFrame(send.Datagram.Span, out QuicConnectionCloseFrame parsedFrame, out int bytesConsumed)
            && parsedFrame.IsApplicationError
            && bytesConsumed == send.Datagram.Length);
    }

    private static (QuicConnectionRuntime Runtime, QuicConnectionSendDatagramEffect Send) CreateOneRttApplicationCloseSend()
    {
        QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime();
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.True(runtime.TlsState.OneRttProtectPacketProtectionMaterial.HasValue);

        QuicConnectionPathIdentity pathIdentity = new("203.0.113.10", RemotePort: 443);
        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 9,
                pathIdentity,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 9).StateChanged);
        Assert.True(runtime.ActivePath.HasValue);

        QuicConnectionCloseMetadata closeMetadata = new(
            TransportErrorCode: null,
            ApplicationErrorCode: 0,
            TriggeringFrameType: null,
            ReasonPhrase: null);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionLocalCloseRequestedEvent(
                ObservedAtTicks: 10,
                closeMetadata),
            nowTicks: 10);

        QuicConnectionSendDatagramEffect send = Assert.IsType<QuicConnectionSendDatagramEffect>(
            Assert.Single(result.Effects, effect => effect is QuicConnectionSendDatagramEffect));
        Assert.Equal(runtime.ActivePath.Value.Identity, send.PathIdentity);
        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.Equal(QuicConnectionSendingMode.CloseOnly, runtime.SendingMode);
        Assert.Equal(closeMetadata, runtime.TerminalState?.Close);
        return (runtime, send);
    }
}
