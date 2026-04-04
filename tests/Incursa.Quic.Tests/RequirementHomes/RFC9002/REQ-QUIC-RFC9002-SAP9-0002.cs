namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-SAP9-0002">When no ack-eliciting packets are in flight, the endpoint MUST send a Handshake packet if it has Handshake keys; otherwise send a padded Initial packet.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-SAP9-0002")]
public sealed class REQ_QUIC_RFC9002_SAP9_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TrySelectPtoTimeAndSpaceMicros_SelectsHandshakeWhenHandshakeKeysExist()
    {
        Assert.True(QuicRecoveryTiming.TrySelectPtoTimeAndSpaceMicros(
            nowMicros: 1_000,
            initialProbeTimeoutMicros: 2_500,
            handshakeProbeTimeoutMicros: 1_800,
            handshakeKeysAvailable: true,
            out ulong selectedPtoTimeMicros,
            out QuicPacketNumberSpace selectedPacketNumberSpace));

        Assert.Equal(2_800UL, selectedPtoTimeMicros);
        Assert.Equal(QuicPacketNumberSpace.Handshake, selectedPacketNumberSpace);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TrySelectPtoTimeAndSpaceMicros_FallsBackToInitialWhenHandshakeKeysAreUnavailable()
    {
        Assert.True(QuicRecoveryTiming.TrySelectPtoTimeAndSpaceMicros(
            nowMicros: 1_000,
            initialProbeTimeoutMicros: 2_500,
            handshakeProbeTimeoutMicros: 1_800,
            handshakeKeysAvailable: false,
            out ulong selectedPtoTimeMicros,
            out QuicPacketNumberSpace selectedPacketNumberSpace));

        Assert.Equal(3_500UL, selectedPtoTimeMicros);
        Assert.Equal(QuicPacketNumberSpace.Initial, selectedPacketNumberSpace);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TrySelectPtoTimeAndSpaceMicros_UsesTheImmediateInitialBoundaryWhenItIsTheOnlyProbe()
    {
        Assert.True(QuicRecoveryTiming.TrySelectPtoTimeAndSpaceMicros(
            nowMicros: 0,
            initialProbeTimeoutMicros: 0,
            handshakeProbeTimeoutMicros: null,
            handshakeKeysAvailable: false,
            out ulong selectedPtoTimeMicros,
            out QuicPacketNumberSpace selectedPacketNumberSpace));

        Assert.Equal(0UL, selectedPtoTimeMicros);
        Assert.Equal(QuicPacketNumberSpace.Initial, selectedPacketNumberSpace);
    }
}
