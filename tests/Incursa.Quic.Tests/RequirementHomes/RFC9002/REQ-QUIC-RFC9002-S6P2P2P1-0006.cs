namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P2P2P1-0006">When the PTO fires and the client does not have Handshake keys, it MUST send an Initial packet in a UDP datagram with a payload of at least 1200 bytes.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S6P2P2P1-0006")]
public sealed class REQ_QUIC_RFC9002_S6P2P2P1_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TrySelectInitialOrHandshakeProbeTimeoutMicros_SelectsInitialWhenHandshakeKeysAreUnavailable()
    {
        Assert.True(QuicRecoveryTiming.TrySelectInitialOrHandshakeProbeTimeoutMicros(
            initialProbeTimeoutMicros: 2_500,
            handshakeProbeTimeoutMicros: null,
            out ulong selectedProbeTimeoutMicros));

        Assert.Equal(2_500UL, selectedProbeTimeoutMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TrySelectInitialOrHandshakeProbeTimeoutMicros_ReturnsFalseWhenBothDeadlinesAreMissing()
    {
        Assert.False(QuicRecoveryTiming.TrySelectInitialOrHandshakeProbeTimeoutMicros(
            initialProbeTimeoutMicros: null,
            handshakeProbeTimeoutMicros: null,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TrySelectInitialOrHandshakeProbeTimeoutMicros_UsesAnImmediateInitialDeadlineWhenItIsTheOnlyOption()
    {
        Assert.True(QuicRecoveryTiming.TrySelectInitialOrHandshakeProbeTimeoutMicros(
            initialProbeTimeoutMicros: 0,
            handshakeProbeTimeoutMicros: null,
            out ulong selectedProbeTimeoutMicros));

        Assert.Equal(0UL, selectedProbeTimeoutMicros);
    }
}
