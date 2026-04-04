namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-S6P2P2P1-0005")]
public sealed class REQ_QUIC_RFC9002_S6P2P2P1_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TrySelectInitialOrHandshakeProbeTimeoutMicros_SelectsHandshakeWhenHandshakeKeysAreAvailable()
    {
        Assert.True(QuicRecoveryTiming.TrySelectInitialOrHandshakeProbeTimeoutMicros(
            initialProbeTimeoutMicros: 3_000,
            handshakeProbeTimeoutMicros: 2_500,
            out ulong selectedProbeTimeoutMicros));

        Assert.Equal(2_500UL, selectedProbeTimeoutMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TrySelectInitialOrHandshakeProbeTimeoutMicros_UsesHandshakeWhenInitialDeadlineIsMissing()
    {
        Assert.True(QuicRecoveryTiming.TrySelectInitialOrHandshakeProbeTimeoutMicros(
            initialProbeTimeoutMicros: null,
            handshakeProbeTimeoutMicros: 2_500,
            out ulong selectedProbeTimeoutMicros));

        Assert.Equal(2_500UL, selectedProbeTimeoutMicros);
    }
}
