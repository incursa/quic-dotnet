namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S11P1-0007">As the AEAD for Initial packets does not provide strong authentication, an endpoint MAY discard an invalid Initial packet.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S11P1-0007")]
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
