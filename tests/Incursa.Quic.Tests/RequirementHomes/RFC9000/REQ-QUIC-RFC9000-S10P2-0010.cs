using System;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P2-0010">After receiving a CONNECTION_CLOSE frame, endpoints MUST enter the draining state.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S10P2-0010")]
public sealed class REQ_QUIC_RFC9000_S10P2_0010
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ReceivedConnectionCloseFrame_TransitionsTheRuntimeToDraining()
    {
        QuicConnectionRuntime runtime = CreateRuntime();
        QuicConnectionCloseMetadata closeMetadata = new(
            TransportErrorCode: QuicTransportErrorCode.ProtocolViolation,
            ApplicationErrorCode: null,
            TriggeringFrameType: 0x1c,
            ReasonPhrase: "peer close");

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionConnectionCloseFrameReceivedEvent(
                ObservedAtTicks: 1,
                closeMetadata),
            nowTicks: 1);

        Assert.Equal(QuicConnectionPhase.Draining, runtime.Phase);
        Assert.Equal(QuicConnectionSendingMode.None, runtime.SendingMode);
        Assert.False(runtime.CanSendOrdinaryPackets);
        Assert.Equal(QuicConnectionCloseOrigin.Remote, runtime.TerminalState?.Origin);
        Assert.Equal(closeMetadata, runtime.TerminalState?.Close);
        Assert.NotNull(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.DrainLifetime));
        Assert.Contains(result.Effects, effect => effect is QuicConnectionNotifyStreamsOfTerminalStateEffect);
        Assert.Contains(result.Effects, effect => effect is QuicConnectionArmTimerEffect arm && arm.TimerKind == QuicConnectionTimerKind.DrainLifetime);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ProtectedApplicationConnectionClosePacket_TransitionsTheRuntimeToDraining()
    {
        // Provenance:
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260422-132744806-server-nginx
        //   runner-logs\nginx_quic-go\handshake\client\log.txt showed the quic-go peer sending
        //   APPLICATION_CLOSE 0x0 immediately after receiving the managed server's 1024-byte response.
        using QuicConnectionRuntime runtime = CreateFinishedServerRuntimeWithActivePath();
        QuicConnectionPathIdentity activePathIdentity = GetActivePathIdentity(runtime);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 10,
                activePathIdentity,
                CreateProtectedApplicationClosePacket(
                    runtime,
                    isApplicationError: true,
                    errorCode: 0,
                    triggeringFrameType: null,
                    reasonPhrase: [],
                    packetNumberBytes: [0x00, 0x00, 0x00, 0x19])),
            nowTicks: 10);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Draining, runtime.Phase);
        Assert.Equal(QuicConnectionSendingMode.None, runtime.SendingMode);
        Assert.False(runtime.CanSendOrdinaryPackets);
        Assert.True(runtime.TerminalState.HasValue);
        Assert.Equal(QuicConnectionCloseOrigin.Remote, runtime.TerminalState.Value.Origin);
        Assert.Null(runtime.TerminalState.Value.Close.TransportErrorCode);
        Assert.Equal(0UL, runtime.TerminalState.Value.Close.ApplicationErrorCode);
        Assert.Null(runtime.TerminalState.Value.Close.TriggeringFrameType);
        Assert.Null(runtime.TerminalState.Value.Close.ReasonPhrase);
        Assert.NotNull(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.DrainLifetime));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ReceivedConnectionCloseFrame_WhileAlreadyDrainingDoesNotChangeStateAgain()
    {
        QuicConnectionRuntime runtime = CreateRuntime();
        QuicConnectionCloseMetadata closeMetadata = new(
            TransportErrorCode: QuicTransportErrorCode.ProtocolViolation,
            ApplicationErrorCode: null,
            TriggeringFrameType: 0x1c,
            ReasonPhrase: "peer close");

        runtime.Transition(
            new QuicConnectionConnectionCloseFrameReceivedEvent(
                ObservedAtTicks: 1,
                closeMetadata),
            nowTicks: 1);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionConnectionCloseFrameReceivedEvent(
                ObservedAtTicks: 2,
                closeMetadata),
            nowTicks: 2);

        Assert.Equal(QuicConnectionPhase.Draining, runtime.Phase);
        Assert.False(result.StateChanged);
        Assert.Empty(result.Effects);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TamperedProtectedApplicationConnectionClosePacket_DoesNotTransitionTheRuntimeToDraining()
    {
        using QuicConnectionRuntime runtime = CreateFinishedServerRuntimeWithActivePath();
        QuicConnectionPathIdentity activePathIdentity = GetActivePathIdentity(runtime);

        byte[] protectedPacket = CreateProtectedApplicationClosePacket(
            runtime,
            isApplicationError: true,
            errorCode: 0,
            triggeringFrameType: null,
            reasonPhrase: [],
            packetNumberBytes: [0x00, 0x00, 0x00, 0x1A]);
        protectedPacket[^1] ^= 0x01;

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 10,
                activePathIdentity,
                protectedPacket),
            nowTicks: 10);

        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.False(runtime.TerminalState.HasValue);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionNotifyStreamsOfTerminalStateEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ReceivedConnectionCloseFrame_WhileClosingPreservesTheTerminalDeadline()
    {
        QuicConnectionRuntime runtime = CreateRuntime();
        QuicConnectionCloseMetadata localCloseMetadata = new(
            TransportErrorCode: QuicTransportErrorCode.NoError,
            ApplicationErrorCode: null,
            TriggeringFrameType: 0x1c,
            ReasonPhrase: "closing");

        runtime.Transition(
            new QuicConnectionLocalCloseRequestedEvent(
                ObservedAtTicks: 1,
                localCloseMetadata),
            nowTicks: 1);

        long closeLifetimeDueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.CloseLifetime)!.Value;

        QuicConnectionCloseMetadata remoteCloseMetadata = new(
            TransportErrorCode: QuicTransportErrorCode.ProtocolViolation,
            ApplicationErrorCode: null,
            TriggeringFrameType: 0x1c,
            ReasonPhrase: "peer close");

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionConnectionCloseFrameReceivedEvent(
                ObservedAtTicks: 2,
                remoteCloseMetadata),
            nowTicks: 2);

        Assert.Equal(QuicConnectionPhase.Draining, runtime.Phase);
        Assert.Null(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.CloseLifetime));
        Assert.Equal(closeLifetimeDueTicks, runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.DrainLifetime));
        Assert.Contains(result.Effects, effect => effect is QuicConnectionArmTimerEffect arm && arm.TimerKind == QuicConnectionTimerKind.DrainLifetime);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionSendDatagramEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ProtectedConnectionClosePacketsAcrossTransportAndApplicationVariants_StillEnterDraining()
    {
        Random random = new(0x1020_0010);

        for (int iteration = 0; iteration < 64; iteration++)
        {
            using QuicConnectionRuntime runtime = CreateFinishedServerRuntimeWithActivePath();
            QuicConnectionPathIdentity activePathIdentity = GetActivePathIdentity(runtime);

            bool isApplicationError = (iteration & 1) == 0;
            ulong errorCode = (ulong)random.Next(0, 1 << 20);
            ulong? triggeringFrameType = isApplicationError ? null : (ulong)(0x08 + (iteration % 8));
            byte[] reasonPhrase = new byte[random.Next(0, 33)];
            random.NextBytes(reasonPhrase);

            QuicConnectionTransitionResult result = runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: 10 + iteration,
                    activePathIdentity,
                    CreateProtectedApplicationClosePacket(
                        runtime,
                        isApplicationError,
                        errorCode,
                        triggeringFrameType,
                        reasonPhrase,
                        packetNumberBytes: [0x00, 0x00, 0x00, (byte)(0x20 + iteration)])),
                nowTicks: 10 + iteration);

            Assert.True(result.StateChanged);
            Assert.Equal(QuicConnectionPhase.Draining, runtime.Phase);
            Assert.True(runtime.TerminalState.HasValue);
            Assert.Equal(QuicConnectionCloseOrigin.Remote, runtime.TerminalState.Value.Origin);

            if (isApplicationError)
            {
                Assert.Null(runtime.TerminalState.Value.Close.TransportErrorCode);
                Assert.Equal(errorCode, runtime.TerminalState.Value.Close.ApplicationErrorCode);
                Assert.Null(runtime.TerminalState.Value.Close.TriggeringFrameType);
            }
            else
            {
                Assert.Equal((QuicTransportErrorCode)errorCode, runtime.TerminalState.Value.Close.TransportErrorCode);
                Assert.Null(runtime.TerminalState.Value.Close.ApplicationErrorCode);
                Assert.Equal(triggeringFrameType, runtime.TerminalState.Value.Close.TriggeringFrameType);
            }
        }
    }

    private static QuicConnectionRuntime CreateRuntime()
    {
        FakeMonotonicClock clock = new(0);
        QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            clock,
            currentProbeTimeoutMicros: 100);

        runtime.Transition(
            new QuicConnectionTransportParametersCommittedEvent(
                ObservedAtTicks: 0,
                TransportFlags: QuicConnectionTransportState.PeerTransportParametersCommitted,
                LocalMaxIdleTimeoutMicros: 200,
                PeerMaxIdleTimeoutMicros: 200,
                CurrentProbeTimeoutMicros: 100),
            nowTicks: 0);

        return runtime;
    }

    private static QuicConnectionRuntime CreateFinishedServerRuntimeWithActivePath()
    {
        QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.10", RemotePort: 443);

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 9,
                pathIdentity,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 9).StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(pathIdentity, runtime.ActivePath.Value.Identity);

        return runtime;
    }

    private static QuicConnectionPathIdentity GetActivePathIdentity(QuicConnectionRuntime runtime)
    {
        return runtime.ActivePath?.Identity
            ?? throw new InvalidOperationException("The finished server runtime did not expose an active path.");
    }

    private static byte[] CreateProtectedApplicationClosePacket(
        QuicConnectionRuntime runtime,
        bool isApplicationError,
        ulong errorCode,
        ulong? triggeringFrameType,
        byte[] reasonPhrase,
        byte[] packetNumberBytes)
    {
        Assert.True(runtime.TlsState.OneRttOpenPacketProtectionMaterial.HasValue);

        QuicConnectionCloseFrame frame = isApplicationError
            ? new QuicConnectionCloseFrame(errorCode, reasonPhrase)
            : new QuicConnectionCloseFrame(errorCode, triggeringFrameType ?? 0, reasonPhrase);
        byte[] payload = QuicFrameTestData.BuildConnectionCloseFrame(frame);

        return QuicS17P3P1TestSupport.CreateProtectedApplicationDataPacket(
            runtime.CurrentPeerDestinationConnectionId.Span,
            packetNumberBytes,
            payload,
            runtime.TlsState.OneRttOpenPacketProtectionMaterial.Value,
            declaredPacketNumberLength: packetNumberBytes.Length);
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
