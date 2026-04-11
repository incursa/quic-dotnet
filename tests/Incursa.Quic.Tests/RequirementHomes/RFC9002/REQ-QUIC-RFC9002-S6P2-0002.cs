namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P2-0002">The PTO MUST be computed separately for each packet number space.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S6P2-0002")]
public sealed class REQ_QUIC_RFC9002_S6P2_0002
{
    public static TheoryData<object> ZeroAckDelayCases => new()
    {
        new ProbeTimeoutSpaceCase(QuicPacketNumberSpace.Initial, false, 2_000),
        new ProbeTimeoutSpaceCase(QuicPacketNumberSpace.ApplicationData, true, 2_000),
    };

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryComputeProbeTimeoutMicros_RejectsApplicationDataBeforeHandshakeConfirmation()
    {
        Assert.False(QuicRecoveryTiming.TryComputeProbeTimeoutMicros(
            QuicPacketNumberSpace.ApplicationData,
            smoothedRttMicros: 1_000,
            rttVarMicros: 200,
            maxAckDelayMicros: 500,
            handshakeConfirmed: false,
            out _));
    }

    [Theory]
    [MemberData(nameof(ZeroAckDelayCases))]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Property")]
    public void TryComputeProbeTimeoutMicros_UsesTheSameBaseTimeoutAtTheAckDelayBoundary(object scenarioValue)
    {
        ProbeTimeoutSpaceCase scenario = (ProbeTimeoutSpaceCase)scenarioValue;

        Assert.True(QuicRecoveryTiming.TryComputeProbeTimeoutMicros(
            scenario.PacketNumberSpace,
            smoothedRttMicros: 1_000,
            rttVarMicros: 200,
            maxAckDelayMicros: 0,
            handshakeConfirmed: scenario.HandshakeConfirmed,
            out ulong probeTimeoutMicros));

        Assert.Equal(scenario.ExpectedProbeTimeoutMicros, probeTimeoutMicros);
    }

    internal sealed record ProbeTimeoutSpaceCase(
        QuicPacketNumberSpace PacketNumberSpace,
        bool HandshakeConfirmed,
        ulong ExpectedProbeTimeoutMicros);
}
