namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S6-0010">Endpoints MUST treat the receipt of a TLS KeyUpdate message as a connection error of type 0x010a, equivalent to a fatal TLS alert of unexpected_message.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9001-S6-0010")]
public sealed class REQ_QUIC_RFC9001_S6_0010
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void KeyUpdateViolationsBecomeConnectionErrors()
    {
        QuicConnectionRuntime runtime = CreateRuntimeWithActivePath();

        QuicTlsTransportBridgeDriver driver = QuicPostHandshakeTicketTestSupport.CreateFinishedClientDriver();
        IReadOnlyList<QuicTlsStateUpdate> updates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.OneRtt,
            QuicPostHandshakeTicketTestSupport.CreateProhibitedKeyUpdatePostHandshakeMessage());

        Assert.Single(updates);
        Assert.Equal(QuicTlsUpdateKind.ProhibitedKeyUpdateViolation, updates[0].Kind);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 10,
                updates[0]),
            nowTicks: 10);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.Equal(QuicConnectionCloseOrigin.Local, runtime.TerminalState?.Origin);
        Assert.Equal(QuicTransportErrorCode.KeyUpdateError, runtime.TerminalState?.Close.TransportErrorCode);
        Assert.Equal(QuicTransportErrorCode.KeyUpdateError, runtime.TlsState.FatalAlertCode);
        Assert.Equal("TLS KeyUpdate was prohibited.", runtime.TlsState.FatalAlertDescription);
        Assert.False(runtime.TlsState.KeyUpdateInstalled);
        Assert.Equal(0U, runtime.TlsState.CurrentOneRttKeyPhase);
        Assert.Contains(result.Effects, effect => effect is QuicConnectionNotifyStreamsOfTerminalStateEffect);
        Assert.Contains(result.Effects, effect => effect is QuicConnectionSendDatagramEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void KeyUpdateViolationsStopLaterPostHandshakeMessagesFromBeingProcessed()
    {
        QuicTlsTransportBridgeDriver driver = QuicPostHandshakeTicketTestSupport.CreateFinishedClientDriver();
        byte[] combinedMessages =
        [
            ..QuicPostHandshakeTicketTestSupport.CreateMalformedKeyUpdatePostHandshakeMessage(),
            ..QuicPostHandshakeTicketTestSupport.CreatePostHandshakeTicketMessage(
                [0xDE, 0xAD, 0xBE, 0xEF],
                [0x01, 0x02]),
        ];

        IReadOnlyList<QuicTlsStateUpdate> updates = driver.ProcessCryptoFrame(QuicTlsEncryptionLevel.OneRtt, combinedMessages);

        Assert.Single(updates);
        Assert.Equal(QuicTlsUpdateKind.ProhibitedKeyUpdateViolation, updates[0].Kind);
        Assert.True(driver.State.IsTerminal);
        Assert.Equal(QuicTransportErrorCode.KeyUpdateError, driver.State.FatalAlertCode);
        Assert.Equal("TLS KeyUpdate was prohibited.", driver.State.FatalAlertDescription);
        Assert.False(driver.State.HasPostHandshakeTicket);
        Assert.False(driver.State.KeyUpdateInstalled);
        Assert.Equal(0U, driver.State.CurrentOneRttKeyPhase);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void KeyUpdateViolationsStillBecomeConnectionErrorsAfterAPostHandshakeTicketHasBeenStored()
    {
        QuicTlsTransportBridgeDriver driver = QuicPostHandshakeTicketTestSupport.CreateFinishedClientDriver();

        IReadOnlyList<QuicTlsStateUpdate> ticketUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.OneRtt,
            QuicPostHandshakeTicketTestSupport.CreatePostHandshakeTicketMessage(
                [0xDE, 0xAD, 0xBE, 0xEF],
                [0x01, 0x02]));

        Assert.Single(ticketUpdates);
        Assert.Equal(QuicTlsUpdateKind.PostHandshakeTicketAvailable, ticketUpdates[0].Kind);
        Assert.True(driver.State.HasPostHandshakeTicket);
        Assert.False(driver.State.IsTerminal);

        IReadOnlyList<QuicTlsStateUpdate> keyUpdateUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.OneRtt,
            QuicPostHandshakeTicketTestSupport.CreateMalformedKeyUpdatePostHandshakeMessage());

        Assert.Single(keyUpdateUpdates);
        Assert.Equal(QuicTlsUpdateKind.ProhibitedKeyUpdateViolation, keyUpdateUpdates[0].Kind);
        Assert.True(driver.State.IsTerminal);
        Assert.Equal(QuicTransportErrorCode.KeyUpdateError, driver.State.FatalAlertCode);
        Assert.Equal("TLS KeyUpdate was prohibited.", driver.State.FatalAlertDescription);
        Assert.False(driver.State.HasPostHandshakeTicket);
        Assert.False(driver.State.KeyUpdateInstalled);
        Assert.Equal(0U, driver.State.CurrentOneRttKeyPhase);
    }

    private static QuicConnectionRuntime CreateRuntimeWithActivePath()
    {
        FakeMonotonicClock clock = new(0);
        QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);

        runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 0,
                new QuicConnectionPathIdentity("203.0.113.10", RemotePort: 443),
                new byte[1200]),
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
