namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual trace slice">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S6P1-0002">Key updates MUST NOT update the header protection key.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9001-S6P1-0002")]
public sealed class REQ_QUIC_RFC9001_S6P1_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RuntimeDerivedSuccessorMaterialRetainsCurrentHeaderProtectionKeys()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);

        QuicTlsPacketProtectionMaterial currentOpenMaterial =
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value;
        QuicTlsPacketProtectionMaterial currentProtectMaterial =
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value;

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryGetRuntimeSuccessorPhaseOnePacketProtectionMaterial(
            runtime,
            out QuicTlsPacketProtectionMaterial successorOpenMaterial,
            out QuicTlsPacketProtectionMaterial successorProtectMaterial));

        AssertUpdatedAeadMaterialRetainsHeaderProtectionKey(currentOpenMaterial, successorOpenMaterial);
        AssertUpdatedAeadMaterialRetainsHeaderProtectionKey(currentProtectMaterial, successorProtectMaterial);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void CapturedPhaseOnePacketDoesNotOpenWhenTheHeaderProtectionKeyRotates()
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

    private static void AssertUpdatedAeadMaterialRetainsHeaderProtectionKey(
        in QuicTlsPacketProtectionMaterial currentMaterial,
        in QuicTlsPacketProtectionMaterial successorMaterial)
    {
        Assert.False(currentMaterial.AeadKey.SequenceEqual(successorMaterial.AeadKey));
        Assert.False(currentMaterial.AeadIv.SequenceEqual(successorMaterial.AeadIv));
        Assert.True(currentMaterial.HeaderProtectionKey.SequenceEqual(successorMaterial.HeaderProtectionKey));
    }
}
