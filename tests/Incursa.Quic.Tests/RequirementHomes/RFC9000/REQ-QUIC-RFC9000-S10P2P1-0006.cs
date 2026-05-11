namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P2P1-0006">To minimize the state that an endpoint maintains for a closing connection, endpoints MAY send the exact same packet in response to any received packet.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S10P2P1-0006")]
public sealed class REQ_QUIC_RFC9000_S10P2P1_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClosingRuntimeReusesTheSamePlaintextConnectionCloseDatagramForRepeatedReplies()
    {
        QuicConnectionRuntime runtime = CreateRuntime();
        QuicConnectionPathIdentity path = new("203.0.113.60", RemotePort: 443);

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 0,
                path,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 0).StateChanged);

        QuicConnectionCloseMetadata closeMetadata = new(
            TransportErrorCode: QuicTransportErrorCode.ProtocolViolation,
            ApplicationErrorCode: null,
            TriggeringFrameType: 0x1c,
            ReasonPhrase: null);

        Assert.True(runtime.Transition(
            new QuicConnectionLocalCloseRequestedEvent(
                ObservedAtTicks: 1,
                closeMetadata),
            nowTicks: 1).StateChanged);

        QuicConnectionTransitionResult firstResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 2,
                path,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 2);

        QuicConnectionTransitionResult secondResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 3,
                path,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 3);

        QuicConnectionSendDatagramEffect firstSend = Assert.IsType<QuicConnectionSendDatagramEffect>(
            Assert.Single(firstResult.Effects, effect => effect is QuicConnectionSendDatagramEffect));
        QuicConnectionSendDatagramEffect secondSend = Assert.IsType<QuicConnectionSendDatagramEffect>(
            Assert.Single(secondResult.Effects, effect => effect is QuicConnectionSendDatagramEffect));
        byte[] expectedDatagram = QuicFrameTestData.BuildConnectionCloseFrame(
            new QuicConnectionCloseFrame(
                QuicTransportErrorCode.ProtocolViolation,
                triggeringFrameType: 0x1c,
                []));

        Assert.True(expectedDatagram.AsSpan().SequenceEqual(firstSend.Datagram.Span));
        Assert.True(firstSend.Datagram.Span.SequenceEqual(secondSend.Datagram.Span));
        Assert.Equal(path, firstSend.PathIdentity);
        Assert.Equal(path, secondSend.PathIdentity);
        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.Equal(QuicConnectionSendingMode.CloseOnly, runtime.SendingMode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ProtectedClosingRuntimeDoesNotPromiseByteForByteReuse()
    {
        using QuicConnectionRuntime runtime = CreateFinishedRuntimeWithActivePath(out QuicConnectionPathIdentity path);

        QuicConnectionCloseMetadata closeMetadata = new(
            TransportErrorCode: QuicTransportErrorCode.ProtocolViolation,
            ApplicationErrorCode: null,
            TriggeringFrameType: 0x1c,
            ReasonPhrase: "closing");

        Assert.True(runtime.Transition(
            new QuicConnectionLocalCloseRequestedEvent(
                ObservedAtTicks: 1,
                closeMetadata),
            nowTicks: 1).StateChanged);

        QuicConnectionTransitionResult firstResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 2,
                path,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 2);

        QuicConnectionTransitionResult secondResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 3,
                path,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 3);

        QuicConnectionSendDatagramEffect firstSend = Assert.IsType<QuicConnectionSendDatagramEffect>(
            Assert.Single(firstResult.Effects, effect => effect is QuicConnectionSendDatagramEffect));
        QuicConnectionSendDatagramEffect secondSend = Assert.IsType<QuicConnectionSendDatagramEffect>(
            Assert.Single(secondResult.Effects, effect => effect is QuicConnectionSendDatagramEffect));

        Assert.False(firstSend.Datagram.Span.SequenceEqual(secondSend.Datagram.Span));
        Assert.Equal(path, firstSend.PathIdentity);
        Assert.Equal(path, secondSend.PathIdentity);
        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.Equal(QuicConnectionSendingMode.CloseOnly, runtime.SendingMode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ClosingRuntimeReusesTheSamePlaintextConnectionCloseDatagramForDifferentAttributedPackets()
    {
        QuicConnectionRuntime runtime = CreateRuntime();
        QuicConnectionPathIdentity firstPath = new("203.0.113.60", RemotePort: 443);
        QuicConnectionPathIdentity secondPath = new("203.0.113.61", RemotePort: 443);
        byte[] receivedPayload = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 0,
                firstPath,
                receivedPayload),
            nowTicks: 0).StateChanged);

        QuicConnectionCloseMetadata closeMetadata = new(
            TransportErrorCode: QuicTransportErrorCode.ProtocolViolation,
            ApplicationErrorCode: null,
            TriggeringFrameType: 0x1c,
            ReasonPhrase: null);

        Assert.True(runtime.Transition(
            new QuicConnectionLocalCloseRequestedEvent(
                ObservedAtTicks: 1,
                closeMetadata),
            nowTicks: 1).StateChanged);

        QuicConnectionTransitionResult firstResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 2,
                firstPath,
                receivedPayload),
            nowTicks: 2);

        QuicConnectionTransitionResult secondResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 3,
                secondPath,
                receivedPayload),
            nowTicks: 3);

        byte[] expectedDatagram = QuicFrameTestData.BuildConnectionCloseFrame(
            new QuicConnectionCloseFrame(
                QuicTransportErrorCode.ProtocolViolation,
                triggeringFrameType: 0x1c,
                []));

        QuicConnectionSendDatagramEffect firstSend = SelectConnectionCloseDatagram(firstResult.Effects, expectedDatagram);
        QuicConnectionSendDatagramEffect secondSend = SelectConnectionCloseDatagram(secondResult.Effects, expectedDatagram);

        Assert.True(expectedDatagram.AsSpan().SequenceEqual(firstSend.Datagram.Span));
        Assert.True(secondSend.Datagram.Span.SequenceEqual(expectedDatagram));
        Assert.True(firstSend.Datagram.Span.SequenceEqual(secondSend.Datagram.Span));
        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.Equal(QuicConnectionSendingMode.CloseOnly, runtime.SendingMode);
    }

    private static QuicConnectionRuntime CreateRuntime()
    {
        byte[] localHandshakePrivateKey = new byte[32];
        localHandshakePrivateKey[^1] = 0x11;

        QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            tlsRole: QuicTlsRole.Server,
            localHandshakePrivateKey: localHandshakePrivateKey);

        Assert.True(runtime.TrySetHandshakeDestinationConnectionId(QuicS17P2P2TestSupport.InitialDestinationConnectionId));
        Assert.True(runtime.TrySetHandshakeSourceConnectionId(QuicS17P2P2TestSupport.InitialSourceConnectionId));

        return runtime;
    }

    private static QuicConnectionRuntime CreateFinishedRuntimeWithActivePath(out QuicConnectionPathIdentity pathIdentity)
    {
        QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime();
        Assert.True(runtime.TlsState.OneRttProtectPacketProtectionMaterial.HasValue);

        pathIdentity = new("203.0.113.61", RemotePort: 443);
        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 0,
                pathIdentity,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 0).StateChanged);

        Assert.True(runtime.ActivePath.HasValue);
        return runtime;
    }

    private static QuicConnectionSendDatagramEffect SelectConnectionCloseDatagram(
        IEnumerable<QuicConnectionEffect> effects,
        byte[] expectedDatagram)
    {
        return Assert.IsType<QuicConnectionSendDatagramEffect>(
            Assert.Single(
                effects.OfType<QuicConnectionSendDatagramEffect>(),
                effect => effect.Datagram.Span.SequenceEqual(expectedDatagram)));
    }
}
