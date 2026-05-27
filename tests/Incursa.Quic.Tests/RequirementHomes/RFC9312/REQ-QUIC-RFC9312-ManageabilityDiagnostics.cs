using Incursa.Quic.Qlog;
using Incursa.Qlog.Quic;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9312-S2-0001">Transport diagnostics MUST expose safe packet header form and packet-type metadata without logging protected payload bytes.</workbench-requirement>
///   <workbench-requirement requirementId="REQ-QUIC-RFC9312-S2-0002">Coalesced UDP datagram processing MUST expose safe packet-count diagnostics.</workbench-requirement>
///   <workbench-requirement requirementId="REQ-QUIC-RFC9312-S3-0001">Connection ID issuance, retirement, and first path use MUST be observable without logging raw connection ID bytes or stateless reset tokens.</workbench-requirement>
///   <workbench-requirement requirementId="REQ-QUIC-RFC9312-S3-0002">NAT rebinding, migration, and path validation MUST emit safe diagnostics for challenge, success, failure, timeout, and path promotion state.</workbench-requirement>
///   <workbench-requirement requirementId="REQ-QUIC-RFC9312-S4-0001">PMTU, ICMP Packet Too Big, UDP error, anti-amplification, close, draining, stateless reset, and spin-bit diagnostics MUST expose only production-safe metadata.</workbench-requirement>
/// </workbench-requirements>
public sealed class REQ_QUIC_RFC9312_ManageabilityDiagnostics
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9312-S2-0001")]
    [Requirement("REQ-QUIC-RFC9312-S2-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PacketHeaderAndCoalescedDiagnostics_MapToQlogWithoutPacketBytes()
    {
        QuicConnectionPathIdentity pathIdentity = CreatePath();
        QuicDiagnosticEvent packetHeaderObserved = QuicDiagnostics.PacketHeaderObserved(
            pathIdentity,
            [0x40, 0x00, 0x00, 0x00],
            packetIndex: 0,
            packetOffset: 0,
            datagramLength: 8);
        QuicDiagnosticEvent coalescedDatagramReceived = QuicDiagnostics.CoalescedDatagramReceived(
            pathIdentity,
            packetCount: 2,
            datagramLength: 8);

        Assert.Equal(QuicDiagnosticKind.PacketHeaderObserved, packetHeaderObserved.Kind);
        Assert.Equal(QuicHeaderForm.Short, packetHeaderObserved.HeaderForm);
        Assert.Equal("short", packetHeaderObserved.PacketType);
        Assert.True(packetHeaderObserved.PacketBytes.IsEmpty);
        Assert.Equal(QuicDiagnosticKind.CoalescedDatagramReceived, coalescedDatagramReceived.Kind);
        Assert.Equal(2, coalescedDatagramReceived.PacketCount);

        QuicQlogDiagnosticsSink sink = EmitToQlog(packetHeaderObserved, coalescedDatagramReceived);

        QlogEventAssert.ContainsEvent(sink, "quic:packet_header_observed");
        QlogEventAssert.ContainsEvent(sink, "quic:coalesced_datagram_received");
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9312-S3-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ConnectionIdDiagnostics_MapToQlogWithoutSensitiveConnectionMetadata()
    {
        QuicConnectionPathIdentity pathIdentity = CreatePath();
        QuicDiagnosticEvent issued = QuicDiagnostics.ConnectionIdIssued(7);
        QuicDiagnosticEvent retired = QuicDiagnostics.ConnectionIdRetired(7);
        QuicDiagnosticEvent usedOnPath = QuicDiagnostics.ConnectionIdUsedOnPath(pathIdentity, 7);

        Assert.Equal(QuicDiagnosticKind.ConnectionIdIssued, issued.Kind);
        Assert.Equal(7UL, issued.ConnectionId);
        Assert.True(issued.PacketBytes.IsEmpty);
        Assert.Equal(QuicDiagnosticKind.ConnectionIdRetired, retired.Kind);
        Assert.Equal(QuicDiagnosticKind.ConnectionIdUsedOnPath, usedOnPath.Kind);
        Assert.Equal(pathIdentity, usedOnPath.PathIdentity);

        QuicQlogDiagnosticsSink sink = EmitToQlog(issued, retired, usedOnPath);

        QlogEventAssert.ContainsEvent(sink, "quic:connection_id_issued");
        QlogEventAssert.ContainsEvent(sink, "quic:connection_id_retired");
        QlogEventAssert.ContainsEvent(sink, "quic:connection_id_used_on_path");
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9312-S3-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PathValidationDiagnostics_MapToQlog()
    {
        QuicConnectionPathIdentity pathIdentity = CreatePath();
        QuicDiagnosticEvent challengeSent = QuicDiagnostics.PathValidationChallengeSent(pathIdentity, 1);
        QuicDiagnosticEvent succeeded = QuicDiagnostics.PathValidationSucceeded(pathIdentity);
        QuicDiagnosticEvent failed = QuicDiagnostics.PathValidationFailed(pathIdentity);
        QuicDiagnosticEvent timedOut = QuicDiagnostics.PathValidationTimedOut(pathIdentity);
        QuicDiagnosticEvent promoted = QuicDiagnostics.PathPromoted(pathIdentity, preserveRecoveryState: true);

        Assert.Equal(QuicDiagnosticKind.PathValidationChallengeSent, challengeSent.Kind);
        Assert.Equal(1UL, challengeSent.ChallengeSendCount);
        Assert.True(succeeded.Succeeded);
        Assert.False(failed.Succeeded);
        Assert.False(timedOut.Succeeded);
        Assert.True(promoted.IsSet);

        QuicQlogDiagnosticsSink sink = EmitToQlog(challengeSent, succeeded, failed, timedOut, promoted);

        QlogEventAssert.ContainsEvent(sink, "quic:path_validation_challenge_sent");
        QlogEventAssert.ContainsEvent(sink, "quic:path_validation_succeeded");
        QlogEventAssert.ContainsEvent(sink, "quic:path_validation_failed");
        QlogEventAssert.ContainsEvent(sink, "quic:path_validation_timed_out");
        QlogEventAssert.ContainsEvent(sink, "quic:path_promoted");
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9312-S4-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PmtuIcmpUdpCloseAndSpinDiagnostics_MapToQlog()
    {
        QuicConnectionPathIdentity pathIdentity = CreatePath();
        QuicDiagnosticEvent spinBit = QuicDiagnostics.SpinBitUpdated(pathIdentity, spinBit: true);
        QuicDiagnosticEvent icmpPacketTooBig = QuicDiagnostics.IcmpPacketTooBigReceived(
            pathIdentity,
            maximumDatagramSizeBytes: 1280,
            accepted: true);
        QuicDiagnosticEvent pmtuUpdated = QuicDiagnostics.PmtuUpdated(
            pathIdentity,
            maximumDatagramSizeBytes: 1280,
            isProvisional: true);
        QuicDiagnosticEvent closeState = QuicDiagnostics.ConnectionCloseStateChanged(
            QuicConnectionCloseOrigin.Remote,
            QuicConnectionPhase.Draining);
        QuicDiagnosticEvent udpReceiveError = QuicDiagnostics.UdpReceiveError("ConnectionReset", 10054);
        QuicDiagnosticEvent udpSendError = QuicDiagnostics.UdpSendError("NetworkUnreachable", 10051);
        QuicDiagnosticEvent antiAmplificationBlocked = QuicDiagnostics.AntiAmplificationBlocked(
            pathIdentity,
            attemptedBytes: 1200,
            remainingSendBudget: 400);
        QuicDiagnosticEvent statelessReset = QuicDiagnostics.AcceptedStatelessReset(pathIdentity, connectionId: 4);

        Assert.Equal(QuicDiagnosticKind.SpinBitUpdated, spinBit.Kind);
        Assert.True(spinBit.IsSet);
        Assert.True(icmpPacketTooBig.Accepted);
        Assert.Equal(1280UL, pmtuUpdated.MaximumDatagramSizeBytes);
        Assert.Equal(QuicConnectionCloseOrigin.Remote, closeState.CloseOrigin);
        Assert.Equal(QuicDiagnosticKind.UdpReceiveError, udpReceiveError.Kind);
        Assert.Equal(QuicDiagnosticKind.UdpSendError, udpSendError.Kind);
        Assert.Equal(1200UL, antiAmplificationBlocked.AttemptedBytes);

        QuicQlogDiagnosticsSink sink = EmitToQlog(
            spinBit,
            icmpPacketTooBig,
            pmtuUpdated,
            closeState,
            udpReceiveError,
            udpSendError,
            antiAmplificationBlocked,
            statelessReset);

        QlogEventAssert.ContainsEvent(sink, "quic:spin_bit_updated");
        QlogEventAssert.ContainsEvent(sink, "quic:icmp_packet_too_big_received");
        QlogEventAssert.ContainsEvent(sink, "quic:pmtu_updated");
        QlogEventAssert.ContainsEvent(sink, "quic:connection_close_state_changed");
        QlogEventAssert.ContainsEvent(sink, "quic:udp_receive_error");
        QlogEventAssert.ContainsEvent(sink, "quic:udp_send_error");
        QlogEventAssert.ContainsEvent(sink, "quic:anti_amplification_blocked");
        QlogEventAssert.ContainsEvent(sink, QlogQuicKnownValues.ConnectionClosedEventName);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9312-S3-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void NatRebindingPathValidation_EmitsChallengeSuccessAndPromotionDiagnostics()
    {
        QuicRecordingDiagnosticsSink diagnosticsSink = new();
        QuicConnectionPathIdentity activePath = CreatePath();
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithConfirmedHandshakeAndActivePath(
            activePath,
            diagnosticsSink);
        QuicConnectionPathIdentity reboundPath = activePath with
        {
            RemotePort = activePath.RemotePort + 1,
        };

        QuicConnectionTransitionResult rebindResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 4,
                reboundPath,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 4);

        Assert.True(rebindResult.StateChanged);
        Assert.Contains(diagnosticsSink.Events, diagnosticEvent =>
            diagnosticEvent.Kind == QuicDiagnosticKind.AddressChangeClassified
            && diagnosticEvent.PathIdentity == reboundPath
            && diagnosticEvent.PathClassification == QuicConnectionPathClassification.MigrationCandidate);
        Assert.Contains(diagnosticsSink.Events, diagnosticEvent =>
            diagnosticEvent.Kind == QuicDiagnosticKind.PathValidationChallengeSent
            && diagnosticEvent.PathIdentity == reboundPath);

        _ = QuicPathMigrationRecoveryTestSupport.ValidatePath(runtime, reboundPath, observedAtTicks: 5);

        Assert.Contains(diagnosticsSink.Events, diagnosticEvent =>
            diagnosticEvent.Kind == QuicDiagnosticKind.PathValidationSucceeded
            && diagnosticEvent.PathIdentity == reboundPath);
        Assert.Contains(diagnosticsSink.Events, diagnosticEvent =>
            diagnosticEvent.Kind == QuicDiagnosticKind.PathPromoted
            && diagnosticEvent.PathIdentity == reboundPath);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9312-S4-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task CloseAsync_EmitsConnectionCloseStateDiagnostic()
    {
        QuicRecordingDiagnosticsSink diagnosticsSink = new();
        QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            diagnosticsSink: diagnosticsSink);
        QuicConnection connection = new(runtime, new TestQuicConnectionOptions());

        await connection.CloseAsync(0x9312);

        Assert.Contains(diagnosticsSink.Events, diagnosticEvent =>
            diagnosticEvent.Kind == QuicDiagnosticKind.ConnectionCloseStateChanged
            && diagnosticEvent.CloseOrigin == QuicConnectionCloseOrigin.Local
            && diagnosticEvent.ConnectionPhase == QuicConnectionPhase.Closing);

        await connection.DisposeAsync();
    }

    private static QuicQlogDiagnosticsSink EmitToQlog(params QuicDiagnosticEvent[] events)
    {
        QuicQlogDiagnosticsSink sink = new(isServer: false);
        foreach (QuicDiagnosticEvent diagnosticEvent in events)
        {
            sink.Emit(diagnosticEvent);
        }

        return sink;
    }

    private static QuicConnectionPathIdentity CreatePath()
    {
        return new(
            RemoteAddress: "203.0.113.10",
            LocalAddress: "198.51.100.3",
            RemotePort: 443,
            LocalPort: 61234);
    }

    private sealed class TestQuicConnectionOptions : QuicConnectionOptions
    {
    }

    private static class QlogEventAssert
    {
        internal static void ContainsEvent(QuicQlogDiagnosticsSink sink, string name)
        {
            Assert.Contains(sink.Trace.Events, qlogEvent => string.Equals(qlogEvent.Name, name, StringComparison.Ordinal));
        }
    }
}
