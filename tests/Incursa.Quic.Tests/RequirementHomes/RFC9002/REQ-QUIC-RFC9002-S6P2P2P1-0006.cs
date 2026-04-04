namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-S6P2P2P1-0006")]
public sealed class REQ_QUIC_RFC9002_S6P2P2P1_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
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
    public void TrySelectInitialOrHandshakeProbeTimeoutMicros_ReturnsFalseWhenBothDeadlinesAreMissing()
    {
        Assert.False(QuicRecoveryTiming.TrySelectInitialOrHandshakeProbeTimeoutMicros(
            initialProbeTimeoutMicros: null,
            handshakeProbeTimeoutMicros: null,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TrySelectInitialOrHandshakeProbeTimeoutMicros_UsesAnImmediateInitialDeadlineWhenItIsTheOnlyOption()
    {
        Assert.True(QuicRecoveryTiming.TrySelectInitialOrHandshakeProbeTimeoutMicros(
            initialProbeTimeoutMicros: 0,
            handshakeProbeTimeoutMicros: null,
            out ulong selectedProbeTimeoutMicros));

        Assert.Equal(0UL, selectedProbeTimeoutMicros);
    }
}
