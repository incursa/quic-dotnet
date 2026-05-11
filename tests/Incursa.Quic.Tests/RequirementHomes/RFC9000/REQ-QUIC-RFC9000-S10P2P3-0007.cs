namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S10P2P3-0007")]
public sealed class REQ_QUIC_RFC9000_S10P2P3_0007
{
    private static readonly byte[] InitialDestinationConnectionId =
    [
        0x83, 0x94, 0xC8, 0xF0,
        0x3E, 0x51, 0x57, 0x08,
    ];

    private static readonly QuicConnectionPathIdentity PathIdentity = new("203.0.113.70", RemotePort: 443);

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S10P2P3-0007")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void InitialPacketWithoutAProcessablePrefixMayBeDiscarded()
    {
        using QuicConnectionRuntime runtime =
            QuicS5P2PacketAssociationTestSupport.CreateServerRuntimeWithInitialProtection(
                InitialDestinationConnectionId);

        byte[] protectedPacket = QuicS5P2PacketAssociationTestSupport.BuildProtectedClientInitialPacket(
            InitialDestinationConnectionId,
            QuicFrameTestData.BuildResetStreamFrame(new QuicResetStreamFrame(0, 1, 0)));

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 0,
                PathIdentity,
                protectedPacket),
            nowTicks: 0);

        Assert.True(result.StateChanged);
        Assert.Empty(result.Effects);
        Assert.NotNull(runtime.ActivePath);
        Assert.Equal(PathIdentity, runtime.ActivePath.Value.Identity);
        Assert.Equal(QuicConnectionPhase.Establishing, runtime.Phase);
        Assert.Null(runtime.TerminalState);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S10P2P3-0007")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void InitialPacketWithAProcessablePrefixBeforeForbiddenFrameStillGeneratesProtocolViolation()
    {
        using QuicConnectionRuntime runtime =
            QuicS5P2PacketAssociationTestSupport.CreateServerRuntimeWithInitialProtection(
                InitialDestinationConnectionId);

        byte[] protectedPacket = QuicS5P2PacketAssociationTestSupport.BuildProtectedClientInitialPacket(
            InitialDestinationConnectionId,
            [
                .. QuicFrameTestData.BuildPingFrame(),
                .. QuicFrameTestData.BuildResetStreamFrame(new QuicResetStreamFrame(0, 1, 0)),
            ]);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 1,
                PathIdentity,
                protectedPacket),
            nowTicks: 1);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.NotNull(runtime.TerminalState);
        Assert.Equal(QuicConnectionCloseOrigin.Local, runtime.TerminalState!.Value.Origin);
        Assert.Equal(QuicTransportErrorCode.ProtocolViolation, runtime.TerminalState.Value.Close.TransportErrorCode);
    }
}
