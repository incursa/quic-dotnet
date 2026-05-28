// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S21P2-0002">Packets that cannot be authenticated MUST be discarded.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S21P2-0002")]
public sealed class REQ_QUIC_RFC9000_S21P2_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerRuntimeDiscardsTamperedInitialPacketWithoutProcessingFrames()
    {
        byte[] initialDestinationConnectionId =
        [
            0x83, 0x94, 0xC8, 0xF0,
            0x3E, 0x51, 0x57, 0x08,
        ];
        QuicConnectionPathIdentity path = new("203.0.113.70", RemotePort: 443);
        byte[] protectedPacket = BuildProtectedClientInitialPacket(initialDestinationConnectionId);
        byte[] tamperedPacket = QuicS5P2PacketAssociationTestSupport.TamperLastByte(protectedPacket);

        using QuicConnectionRuntime runtime = QuicS5P2PacketAssociationTestSupport.CreateServerRuntimeWithInitialProtection(
            initialDestinationConnectionId);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 0,
                path,
                tamperedPacket),
            nowTicks: 0);

        Assert.True(result.StateChanged);
        Assert.Empty(result.Effects);
        Assert.NotNull(runtime.ActivePath);
        Assert.Equal(path, runtime.ActivePath.Value.Identity);
        Assert.Equal(QuicConnectionPhase.Establishing, runtime.Phase);
        Assert.False(runtime.TlsState.InitialKeysAvailable);
        Assert.False(runtime.TlsState.HandshakeKeysAvailable);
        Assert.Null(runtime.TlsState.HandshakeMessageType);
        Assert.False(runtime.TlsState.PeerHandshakeTranscriptCompleted);
        Assert.Empty(runtime.SendRuntime.SentPackets);
        Assert.Null(runtime.TerminalState);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerRuntimeProcessesValidClientInitialPacketInsteadOfDiscardingIt()
    {
        byte[] initialDestinationConnectionId =
        [
            0x83, 0x94, 0xC8, 0xF0,
            0x3E, 0x51, 0x57, 0x08,
        ];
        QuicConnectionPathIdentity path = new("203.0.113.71", RemotePort: 443);
        byte[] protectedPacket = BuildProtectedClientInitialPacket(initialDestinationConnectionId);

        using QuicConnectionRuntime runtime = QuicS5P2PacketAssociationTestSupport.CreateServerRuntimeWithInitialProtection(
            initialDestinationConnectionId);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 1,
                path,
                protectedPacket),
            nowTicks: 1);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Draining, runtime.Phase);
        Assert.NotNull(runtime.TerminalState);
        Assert.Equal(QuicConnectionCloseOrigin.Remote, runtime.TerminalState!.Value.Origin);
        Assert.Equal(QuicTransportErrorCode.NoError, runtime.TerminalState.Value.Close.TransportErrorCode);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionDiscardConnectionStateEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ServerRuntimeDiscardsTruncatedInitialPacketWithoutProcessingFrames()
    {
        byte[] initialDestinationConnectionId =
        [
            0x83, 0x94, 0xC8, 0xF0,
            0x3E, 0x51, 0x57, 0x08,
        ];
        QuicConnectionPathIdentity path = new("203.0.113.72", RemotePort: 443);
        byte[] protectedPacket = BuildProtectedClientInitialPacket(initialDestinationConnectionId);
        byte[] truncatedPacket = protectedPacket[..^1];

        using QuicConnectionRuntime runtime = QuicS5P2PacketAssociationTestSupport.CreateServerRuntimeWithInitialProtection(
            initialDestinationConnectionId);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 2,
                path,
                truncatedPacket),
            nowTicks: 2);

        Assert.True(result.StateChanged);
        Assert.Empty(result.Effects);
        Assert.NotNull(runtime.ActivePath);
        Assert.Equal(path, runtime.ActivePath.Value.Identity);
        Assert.Equal(QuicConnectionPhase.Establishing, runtime.Phase);
        Assert.False(runtime.TlsState.InitialKeysAvailable);
        Assert.False(runtime.TlsState.HandshakeKeysAvailable);
        Assert.Null(runtime.TlsState.HandshakeMessageType);
        Assert.False(runtime.TlsState.PeerHandshakeTranscriptCompleted);
        Assert.Empty(runtime.SendRuntime.SentPackets);
        Assert.Null(runtime.TerminalState);
    }

    private static byte[] BuildProtectedClientInitialPacket(ReadOnlySpan<byte> initialDestinationConnectionId)
    {
        QuicConnectionCloseFrame closeFrame = new(
            QuicTransportErrorCode.NoError,
            triggeringFrameType: 0x02,
            []);

        return QuicS5P2PacketAssociationTestSupport.BuildProtectedClientInitialPacket(
            initialDestinationConnectionId,
            QuicFrameTestData.BuildConnectionCloseFrame(closeFrame));
    }
}
