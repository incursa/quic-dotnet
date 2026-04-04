namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P2P1-0005">An endpoint MUST NOT set its PTO timer for the Application Data packet number space until the handshake is confirmed.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S6P2P1-0005")]
public sealed class REQ_QUIC_RFC9002_S6P2P1_0005
{
    public static TheoryData<ApplicationDataPtoGateCase> ApplicationDataPtoGateCases => new()
    {
        new(false, false, 0),
        new(true, true, 2_500),
    };

    [Theory]
    [MemberData(nameof(ApplicationDataPtoGateCases))]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Property")]
    public void TryComputeProbeTimeoutMicros_GatesApplicationDataPtoOnHandshakeConfirmation(ApplicationDataPtoGateCase scenario)
    {
        Assert.Equal(scenario.ExpectedAccepted, QuicRecoveryTiming.TryComputeProbeTimeoutMicros(
            QuicPacketNumberSpace.ApplicationData,
            smoothedRttMicros: 1_000,
            rttVarMicros: 250,
            maxAckDelayMicros: 500,
            handshakeConfirmed: scenario.HandshakeConfirmed,
            out ulong probeTimeoutMicros,
            timerGranularityMicros: 1));

        Assert.Equal(scenario.ExpectedProbeTimeoutMicros, probeTimeoutMicros);
    }

    public sealed record ApplicationDataPtoGateCase(
        bool HandshakeConfirmed,
        bool ExpectedAccepted,
        ulong ExpectedProbeTimeoutMicros);
}
