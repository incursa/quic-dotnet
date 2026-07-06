// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="RFC9000-S11-1-P5-S1-R01">As the AEAD for Initial packets does not provide strong authentication, an endpoint MAY discard an invalid Initial packet.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S11-1-P5-S1-R01")]
public sealed class REQ_QUIC_RFC9000_S11P1_0007
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerRuntimeDiscardsClientProtectedInitialPacketWithoutProcessingFrames()
    {
        byte[] initialDestinationConnectionId =
        [
            0x83, 0x94, 0xC8, 0xF0,
            0x3E, 0x51, 0x57, 0x08,
        ];
        QuicConnectionPathIdentity path = new("203.0.113.70", RemotePort: 443);

        byte[] protectedInitialPacket = CreateProtectedInitialPacket(
            initialDestinationConnectionId,
            QuicTlsRole.Client);

        QuicConnectionRuntime runtime = CreateServerRuntime(initialDestinationConnectionId);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 0,
                path,
                protectedInitialPacket),
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
        using QuicConnectionRuntime runtime =
            QuicS5P2PacketAssociationTestSupport.CreateServerRuntimeWithInitialProtection(initialDestinationConnectionId);
        QuicConnectionPathIdentity path = new("203.0.113.72", RemotePort: 443);
        QuicConnectionCloseFrame closeFrame = new(QuicTransportErrorCode.NoError, triggeringFrameType: 0x02, []);
        byte[] protectedPacket = QuicS5P2PacketAssociationTestSupport.BuildProtectedClientInitialPacket(
            initialDestinationConnectionId,
            QuicFrameTestData.BuildConnectionCloseFrame(closeFrame));

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
    public void ServerRuntimeDiscardsTruncatedInvalidInitialPacketWithoutProcessingFrames()
    {
        byte[] initialDestinationConnectionId =
        [
            0x83, 0x94, 0xC8, 0xF0,
            0x3E, 0x51, 0x57, 0x08,
        ];
        QuicConnectionPathIdentity path = new("203.0.113.73", RemotePort: 443);
        byte[] protectedPacket = CreateProtectedInitialPacket(
            initialDestinationConnectionId,
            QuicTlsRole.Client);
        byte[] truncatedPacket = protectedPacket[..^1];

        using QuicConnectionRuntime runtime = CreateServerRuntime(initialDestinationConnectionId);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 2,
                path,
                truncatedPacket),
            nowTicks: 2);

        Assert.Null(runtime.TerminalState);
        Assert.Equal(QuicConnectionPhase.Establishing, runtime.Phase);
        Assert.Empty(runtime.SendRuntime.SentPackets);
        Assert.Equal(0, runtime.TlsState.InitialIngressCryptoBuffer.BufferedBytes);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionDiscardConnectionStateEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ServerRuntimeDiscardsInvalidInitialPacketsWithoutProcessingFrames()
    {
        byte[] initialDestinationConnectionId =
        [
            0x83, 0x94, 0xC8, 0xF0,
            0x3E, 0x51, 0x57, 0x08,
        ];
        byte[] protectedPacket = CreateProtectedInitialPacket(
            initialDestinationConnectionId,
            QuicTlsRole.Client);
        byte[][] invalidPackets =
        [
            protectedPacket[..^1],
            protectedPacket[..^QuicInitialPacketProtection.AuthenticationTagLength],
            TamperProtectedPacket(protectedPacket, protectedPacket.Length - 1, 0x80),
            TamperProtectedPacket(protectedPacket, protectedPacket.Length / 2, 0x40),
        ];

        foreach (byte[] invalidPacket in invalidPackets)
        {
            QuicConnectionPathIdentity path = new("203.0.113.76", RemotePort: 443);
            using QuicConnectionRuntime runtime = CreateServerRuntime(initialDestinationConnectionId);

            QuicConnectionTransitionResult result = runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: 3,
                    path,
                    invalidPacket),
                nowTicks: 3);

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
            Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionDiscardConnectionStateEffect);
        }
    }

    private static byte[] CreateProtectedInitialPacket(
        ReadOnlySpan<byte> initialDestinationConnectionId,
        QuicTlsRole protectionRole)
    {
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
            plaintextPayload:
            [
                0x10, 0x11, 0x12, 0x13, 0x14,
                0x15, 0x16, 0x17, 0x18, 0x19,
                0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
                0x1F, 0x20, 0x21, 0x22, 0x23,
            ]);

        Assert.True(QuicInitialPacketProtection.TryCreate(
            protectionRole,
            initialDestinationConnectionId,
            out QuicInitialPacketProtection protection));

        byte[] protectedPacket = new byte[plaintextPacket.Length + QuicInitialPacketProtection.AuthenticationTagLength];
        Assert.True(protection.TryProtect(plaintextPacket, protectedPacket, out int bytesWritten));
        Assert.Equal(protectedPacket.Length, bytesWritten);

        return protectedPacket;
    }

    private static byte[] TamperProtectedPacket(byte[] packet, int offset, byte mask)
    {
        byte[] tamperedPacket = packet.ToArray();
        tamperedPacket[offset] ^= mask;
        return tamperedPacket;
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
