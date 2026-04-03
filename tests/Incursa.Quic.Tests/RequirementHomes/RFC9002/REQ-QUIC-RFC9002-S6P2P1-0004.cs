namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-S6P2P1-0004")]
public sealed class REQ_QUIC_RFC9002_S6P2P1_0004
{
    public static TheoryData<SharedDeadlineCase> SharedDeadlineCases => new()
    {
        new(2_500, 2_500, 2_500),
        new(3_000, 3_000, 3_000),
    };

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TrySelectInitialOrHandshakeProbeTimeoutMicros_ReturnsFalseWhenBothTimersAreMissing()
    {
        Assert.False(QuicRecoveryTiming.TrySelectInitialOrHandshakeProbeTimeoutMicros(
            initialProbeTimeoutMicros: null,
            handshakeProbeTimeoutMicros: null,
            out _));
    }

    [Theory]
    [MemberData(nameof(SharedDeadlineCases))]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Property")]
    public void TrySelectInitialOrHandshakeProbeTimeoutMicros_UsesTheSharedDeadlineWhenBothTimersMatch(SharedDeadlineCase scenario)
    {
        Assert.True(QuicRecoveryTiming.TrySelectInitialOrHandshakeProbeTimeoutMicros(
            initialProbeTimeoutMicros: scenario.InitialProbeTimeoutMicros,
            handshakeProbeTimeoutMicros: scenario.HandshakeProbeTimeoutMicros,
            out ulong selectedProbeTimeoutMicros));

        Assert.Equal(scenario.ExpectedSelectedProbeTimeoutMicros, selectedProbeTimeoutMicros);
    }

    public sealed record SharedDeadlineCase(
        ulong InitialProbeTimeoutMicros,
        ulong HandshakeProbeTimeoutMicros,
        ulong ExpectedSelectedProbeTimeoutMicros);
}
