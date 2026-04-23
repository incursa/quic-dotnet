namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual trace slice">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S6P4-0002">Packets with higher packet numbers MUST be protected with the same or newer packet protection keys than packets with lower packet numbers.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9001-S6P4-0002")]
public sealed class REQ_QUIC_RFC9001_S6P4_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void LocalFirstKeyUpdateProtectsHigherPacketNumbersWithNewKeys()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);

        QuicTlsPacketProtectionMaterial priorProtectMaterial =
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value;
        QuicHandshakeFlowCoordinator coordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();

        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            QuicRfc9001KeyPhaseTestSupport.CreatePingPayload(),
            priorProtectMaterial,
            keyPhase: false,
            out ulong lowerPacketNumber,
            out byte[] lowerProtectedPacket));

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryInstallRuntimeOneRttKeyUpdate(runtime));
        QuicTlsPacketProtectionMaterial installedProtectMaterial =
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value;

        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            QuicRfc9001KeyPhaseTestSupport.CreatePingPayload(),
            installedProtectMaterial,
            keyPhase: true,
            out ulong higherPacketNumber,
            out byte[] higherProtectedPacket));

        Assert.True(higherPacketNumber > lowerPacketNumber);
        AssertPacketOpensWithMaterialAndPhase(lowerProtectedPacket, priorProtectMaterial, expectedKeyPhase: false);
        AssertPacketOpensWithMaterialAndPhase(higherProtectedPacket, installedProtectMaterial, expectedKeyPhase: true);
        AssertPacketDoesNotOpenWithMaterial(higherProtectedPacket, priorProtectMaterial);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void LocalFirstKeyUpdateDoesNotProtectHigherPacketNumbersWithOldKeys()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);

        QuicTlsPacketProtectionMaterial priorProtectMaterial =
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value;

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryInstallRuntimeOneRttKeyUpdate(runtime));
        QuicTlsPacketProtectionMaterial installedProtectMaterial =
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value;

        QuicHandshakeFlowCoordinator coordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();
        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            QuicRfc9001KeyPhaseTestSupport.CreatePingPayload(),
            installedProtectMaterial,
            keyPhase: true,
            out ulong packetNumber,
            out byte[] protectedPacket));

        AssertPacketDoesNotOpenWithMaterial(protectedPacket, priorProtectMaterial);
        AssertPacketOpensWithMaterialAndPhase(protectedPacket, installedProtectMaterial, expectedKeyPhase: true);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzLocalFirstKeyUpdate_RandomizedPayloadsProtectHigherPacketNumbersWithNewKeys()
    {
        Random random = new(unchecked((int)0x9001_6402));

        for (int iteration = 0; iteration < 32; iteration++)
        {
            using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
            QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);

            QuicTlsPacketProtectionMaterial priorProtectMaterial =
                runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value;
            QuicHandshakeFlowCoordinator coordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();

            Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
                CreateAckElicitingPayload(random.Next(1, 96)),
                priorProtectMaterial,
                keyPhase: false,
                out ulong lowerPacketNumber,
                out _));

            Assert.True(QuicRfc9001KeyPhaseTestSupport.TryInstallRuntimeOneRttKeyUpdate(runtime));
            QuicTlsPacketProtectionMaterial installedProtectMaterial =
                runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value;

            Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
                CreateAckElicitingPayload(random.Next(1, 96)),
                installedProtectMaterial,
                keyPhase: true,
                out ulong higherPacketNumber,
                out byte[] higherProtectedPacket));

            Assert.True(higherPacketNumber > lowerPacketNumber);
            AssertPacketDoesNotOpenWithMaterial(higherProtectedPacket, priorProtectMaterial);
            AssertPacketOpensWithMaterialAndPhase(higherProtectedPacket, installedProtectMaterial, expectedKeyPhase: true);
        }
    }

    private static void AssertPacketOpensWithMaterialAndPhase(
        byte[] protectedPacket,
        QuicTlsPacketProtectionMaterial material,
        bool expectedKeyPhase)
    {
        QuicHandshakeFlowCoordinator coordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();
        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            material,
            out byte[] openedPacket,
            out _,
            out _,
            out bool observedKeyPhase));

        Assert.Equal(expectedKeyPhase, observedKeyPhase);
        Assert.True(QuicPacketParser.TryParseShortHeader(openedPacket, out QuicShortHeaderPacket header));
        Assert.Equal(expectedKeyPhase, header.KeyPhase);
    }

    private static void AssertPacketDoesNotOpenWithMaterial(
        byte[] protectedPacket,
        QuicTlsPacketProtectionMaterial material)
    {
        QuicHandshakeFlowCoordinator coordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();
        Assert.False(coordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            material,
            out _,
            out _,
            out _,
            out _));
    }

    private static byte[] CreateAckElicitingPayload(int payloadLength)
    {
        byte[] payload = new byte[payloadLength];
        Assert.True(QuicFrameCodec.TryFormatPingFrame(payload, out int bytesWritten));
        Assert.Equal(1, bytesWritten);
        return payload;
    }
}
