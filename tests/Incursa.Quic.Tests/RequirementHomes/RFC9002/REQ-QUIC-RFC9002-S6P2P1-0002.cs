namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P2P1-0002">When the PTO is armed for the Initial or Handshake packet number spaces, the max_ack_delay in the PTO computation MUST be set to 0.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S6P2P1-0002")]
public sealed class REQ_QUIC_RFC9002_S6P2P1_0002
{
    public static TheoryData<EarlySpaceAckDelayCase> EarlySpaceAckDelayCases => new()
    {
        new(QuicPacketNumberSpace.Initial, 0, 2_000),
        new(QuicPacketNumberSpace.Handshake, 500, 2_000),
    };

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryComputeProbeTimeoutMicros_PreservesMaxAckDelayForApplicationDataSpace()
    {
        Assert.True(QuicRecoveryTiming.TryComputeProbeTimeoutMicros(
            QuicPacketNumberSpace.ApplicationData,
            smoothedRttMicros: 1_000,
            rttVarMicros: 250,
            maxAckDelayMicros: 500,
            handshakeConfirmed: true,
            out ulong probeTimeoutMicros,
            timerGranularityMicros: 1));

        Assert.Equal(2_500UL, probeTimeoutMicros);
    }

    [Theory]
    [MemberData(nameof(EarlySpaceAckDelayCases))]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Property")]
    public void TryComputeProbeTimeoutMicros_ZeroesMaxAckDelayInTheInitialAndHandshakeSpaces(EarlySpaceAckDelayCase scenario)
    {
        Assert.True(QuicRecoveryTiming.TryComputeProbeTimeoutMicros(
            scenario.PacketNumberSpace,
            smoothedRttMicros: 1_000,
            rttVarMicros: 250,
            maxAckDelayMicros: scenario.ProvidedMaxAckDelayMicros,
            handshakeConfirmed: false,
            out ulong probeTimeoutMicros,
            timerGranularityMicros: 1));

        Assert.Equal(scenario.ExpectedProbeTimeoutMicros, probeTimeoutMicros);
    }

    public sealed record EarlySpaceAckDelayCase(
        QuicPacketNumberSpace PacketNumberSpace,
        ulong ProvidedMaxAckDelayMicros,
        ulong ExpectedProbeTimeoutMicros);
}
