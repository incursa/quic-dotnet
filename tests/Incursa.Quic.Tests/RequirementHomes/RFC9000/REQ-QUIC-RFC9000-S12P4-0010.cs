// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S12P4-0010">Only a CONNECTION_CLOSE frame of type 0x1c MAY appear in Initial or Handshake packets.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S12P4-0010")]
public sealed class REQ_QUIC_RFC9000_S12P4_0010
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S20P1-0002")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    [Requirement("REQ-QUIC-RFC9000-S20P1-0002")]
    public void TryHandleInitialPacketReceived_AllowsTransportConnectionCloseInAnInitialPacket()
    {
        byte[] initialDestinationConnectionId =
        [
            0x83, 0x94, 0xC8, 0xF0,
            0x3E, 0x51, 0x57, 0x08,
        ];
        QuicConnectionRuntime runtime = CreateServerRuntime(initialDestinationConnectionId);
        QuicConnectionPathIdentity path = new("203.0.113.70", RemotePort: 443);

        byte[] transportConnectionClose = QuicFrameTestData.BuildConnectionCloseFrame(
            new QuicConnectionCloseFrame(QuicTransportErrorCode.NoError, triggeringFrameType: 0x02, []));
        byte[] protectedInitialPacket = CreateProtectedInitialPacket(initialDestinationConnectionId, transportConnectionClose);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 0,
                path,
                protectedInitialPacket),
            nowTicks: 0);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Draining, runtime.Phase);
        Assert.NotNull(runtime.TerminalState);
        Assert.Equal(QuicConnectionCloseOrigin.Remote, runtime.TerminalState!.Value.Origin);
        Assert.Equal(QuicTransportErrorCode.NoError, runtime.TerminalState.Value.Close.TransportErrorCode);
        Assert.Null(runtime.TerminalState.Value.Close.ApplicationErrorCode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryHandleInitialPacketReceived_ClosesTheConnectionWithProtocolViolationWhenItReceivesAnApplicationConnectionCloseFrame()
    {
        byte[] initialDestinationConnectionId =
        [
            0x83, 0x94, 0xC8, 0xF0,
            0x3E, 0x51, 0x57, 0x08,
        ];
        QuicConnectionRuntime runtime = CreateServerRuntime(initialDestinationConnectionId);
        QuicConnectionPathIdentity path = new("203.0.113.70", RemotePort: 443);

        byte[] applicationConnectionClose = QuicFrameTestData.BuildConnectionCloseFrame(
            new QuicConnectionCloseFrame(0x1234, []));
        byte[] protectedInitialPacket = CreateProtectedInitialPacket(initialDestinationConnectionId, applicationConnectionClose);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 1,
                path,
                protectedInitialPacket),
            nowTicks: 1);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.NotNull(runtime.TerminalState);
        Assert.Equal(QuicConnectionCloseOrigin.Local, runtime.TerminalState!.Value.Origin);
        Assert.Equal(QuicTransportErrorCode.ProtocolViolation, runtime.TerminalState.Value.Close.TransportErrorCode);
        Assert.Null(runtime.TerminalState.Value.Close.ApplicationErrorCode);
    }

    private static byte[] CreateProtectedInitialPacket(
        ReadOnlySpan<byte> initialDestinationConnectionId,
        ReadOnlySpan<byte> plaintextPayload)
    {
        byte[] paddedPlaintextPayload = new byte[Math.Max(plaintextPayload.Length, 24)];
        plaintextPayload.CopyTo(paddedPlaintextPayload);

        byte[] plaintextPacket = QuicInitialPacketProtectionTestData.BuildInitialPlaintextPacket(
            destinationConnectionId: initialDestinationConnectionId,
            sourceConnectionId:
            [
                0x21, 0x22, 0x23, 0x24,
            ],
            token: [],
            packetNumber:
            [
                0x01,
            ],
            plaintextPayload: paddedPlaintextPayload);

        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            initialDestinationConnectionId,
            out QuicInitialPacketProtection protection));

        byte[] protectedPacket = new byte[plaintextPacket.Length + QuicInitialPacketProtection.AuthenticationTagLength];
        Assert.True(protection.TryProtect(plaintextPacket, protectedPacket, out int bytesWritten));
        Assert.Equal(protectedPacket.Length, bytesWritten);

        return protectedPacket;
    }

    private static QuicConnectionRuntime CreateServerRuntime(ReadOnlySpan<byte> initialDestinationConnectionId)
    {
        QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            new FakeMonotonicClock(0),
            currentProbeTimeoutMicros: 100,
            tlsRole: QuicTlsRole.Server);

        Assert.True(runtime.TryConfigureInitialPacketProtection(initialDestinationConnectionId));
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
