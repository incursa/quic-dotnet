namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S6-0007">An endpoint that notices a changed Key Phase bit MUST decrypt the packet that contains the changed value.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9001-S6-0007")]
public sealed class REQ_QUIC_RFC9001_S6_0007
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryOpenProtectedApplicationDataPacket_DecryptsTheFirstObservedPhaseOnePacketWithSuccessorMaterial()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryGetRuntimeSuccessorPhaseOnePacketProtectionMaterial(
            runtime,
            out QuicTlsPacketProtectionMaterial successorOpenMaterial,
            out _));

        byte[] protectedPacket = QuicRfc9001KeyPhaseTestSupport.CreateSuccessorPhaseOneApplicationPacket(successorOpenMaterial);

        QuicHandshakeFlowCoordinator coordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();

        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            successorOpenMaterial,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength,
            out bool observedKeyPhase));

        Assert.True(observedKeyPhase);
        Assert.True(QuicPacketParser.TryParseShortHeader(openedPacket, out QuicShortHeaderPacket parsedHeader));
        Assert.True(parsedHeader.KeyPhase);
        Assert.NotEmpty(openedPacket);
        Assert.True(payloadOffset > 0);
        Assert.True(payloadLength > 0);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryOpenProtectedApplicationDataPacket_DoesNotDecryptATamperedSuccessorPacket()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryGetRuntimeSuccessorPhaseOnePacketProtectionMaterial(
            runtime,
            out QuicTlsPacketProtectionMaterial successorOpenMaterial,
            out _));

        byte[] protectedPacket = QuicRfc9001KeyPhaseTestSupport.CreateTamperedSuccessorPhaseOneApplicationPacket(successorOpenMaterial);

        QuicHandshakeFlowCoordinator coordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();

        Assert.False(coordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            successorOpenMaterial,
            out _,
            out _,
            out _,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CapturedTransferPhaseOnePacketDecryptsWithSuccessorAeadMaterialAndTheRetainedCurrentHeaderProtectionKey()
    {
        Assert.True(QuicCapturedInteropTransferEvidence.TryCreateTransferPhaseOneServerOpenMaterialWithRetainedHeaderProtectionKey(
            out QuicTlsPacketProtectionMaterial successorOpenMaterial));

        Assert.True(QuicCapturedInteropTransferEvidence.TryOpenTransferPhaseOneServerPacket(
            QuicCapturedInteropTransferEvidence.QuicGoTransferKeyUpdatePacket101Protected,
            successorOpenMaterial,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength,
            out bool observedKeyPhase));

        Assert.True(observedKeyPhase);
        Assert.Equal(
            QuicCapturedInteropTransferEvidence.QuicGoTransferKeyUpdatePacket101Payload,
            openedPacket.AsSpan(payloadOffset, payloadLength).ToArray());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void CapturedTransferPhaseOnePacketDoesNotDecryptWhenTheHeaderProtectionKeyAlsoRotates()
    {
        Assert.True(QuicCapturedInteropTransferEvidence.TryCreateTransferPhaseOneServerOpenMaterialWithDerivedHeaderProtectionKey(
            out QuicTlsPacketProtectionMaterial successorOpenMaterial));

        Assert.False(QuicCapturedInteropTransferEvidence.TryOpenTransferPhaseOneServerPacket(
            QuicCapturedInteropTransferEvidence.QuicGoTransferKeyUpdatePacket101Protected,
            successorOpenMaterial,
            out _,
            out _,
            out _,
            out _));
    }
}
