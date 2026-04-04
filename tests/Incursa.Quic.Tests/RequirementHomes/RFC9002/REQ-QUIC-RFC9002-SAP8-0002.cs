namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-SAP8-0002">If no ack-eliciting packets are in flight, GetPtoTimeAndSpace MUST start PTO timing from now() + duration and select Handshake when handshake keys exist, otherwise Initial.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-SAP8-0002")]
public sealed class REQ_QUIC_RFC9002_SAP8_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TrySelectPtoTimeAndSpaceMicros_UsesHandshakeWhenHandshakeKeysAreAvailable()
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
    public void TrySelectPtoTimeAndSpaceMicros_ReturnsFalseWhenNeitherSpaceHasAptoDeadline()
    {
        Assert.False(QuicRecoveryTiming.TrySelectPtoTimeAndSpaceMicros(
            nowMicros: 1_000,
            initialProbeTimeoutMicros: null,
            handshakeProbeTimeoutMicros: null,
            handshakeKeysAvailable: false,
            out _,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TrySelectPtoTimeAndSpaceMicros_StartsFromNowAtTheImmediateBoundary()
    {
        Assert.True(QuicRecoveryTiming.TrySelectPtoTimeAndSpaceMicros(
            nowMicros: 0,
            initialProbeTimeoutMicros: 1,
            handshakeProbeTimeoutMicros: null,
            handshakeKeysAvailable: false,
            out ulong selectedPtoTimeMicros,
            out QuicPacketNumberSpace selectedPacketNumberSpace));

        Assert.Equal(1UL, selectedPtoTimeMicros);
        Assert.Equal(QuicPacketNumberSpace.Initial, selectedPacketNumberSpace);
    }
}
