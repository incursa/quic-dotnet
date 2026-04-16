namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S6-0005">The Key Phase bit MUST allow a recipient to detect a change in keying material without needing to receive the first packet that triggered the change.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9001-S6-0005")]
public sealed class REQ_QUIC_RFC9001_S6_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryOpenProtectedApplicationDataPacket_DetectsTheChangedKeyPhaseWithoutTheTriggeringPacket()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);

        Assert.False(runtime.TlsState.KeyUpdateInstalled);
        Assert.Equal(0U, runtime.TlsState.CurrentOneRttKeyPhase);
        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryGetRuntimeSuccessorPhaseOnePacketProtectionMaterial(
            runtime,
            out QuicTlsPacketProtectionMaterial successorOpenMaterial,
            out _));

        QuicHandshakeFlowCoordinator coordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();
        byte[] protectedPacket = QuicRfc9001KeyPhaseTestSupport.CreateSuccessorPhaseOneApplicationPacket(successorOpenMaterial);

        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            successorOpenMaterial,
            out byte[] openedPacket,
            out _,
            out _,
            out bool observedKeyPhase));

        Assert.True(observedKeyPhase);
        Assert.True(QuicPacketParser.TryParseShortHeader(openedPacket, out QuicShortHeaderPacket parsedHeader));
        Assert.True(parsedHeader.KeyPhase);
        Assert.False(runtime.TlsState.KeyUpdateInstalled);
        Assert.Equal(0U, runtime.TlsState.CurrentOneRttKeyPhase);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryOpenProtectedApplicationDataPacket_DoesNotReportAKeyPhaseChangeForPhaseZeroPackets()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);

        QuicTlsPacketProtectionMaterial currentOpenMaterial = runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value;
        QuicHandshakeFlowCoordinator coordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();

        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            CreatePingPayload(),
            currentOpenMaterial,
            keyPhase: false,
            out byte[] protectedPacket));

        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            currentOpenMaterial,
            out byte[] openedPacket,
            out _,
            out _,
            out bool observedKeyPhase));

        Assert.False(observedKeyPhase);
        Assert.True(QuicPacketParser.TryParseShortHeader(openedPacket, out QuicShortHeaderPacket parsedHeader));
        Assert.False(parsedHeader.KeyPhase);
    }

    private static byte[] CreatePingPayload()
    {
        byte[] payload = new byte[1];
        Assert.True(QuicFrameCodec.TryFormatPingFrame(payload, out int bytesWritten));
        Assert.Equal(1, bytesWritten);
        return payload;
    }
}
