namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P4-0008">If the spin bit is enabled for the path, the endpoint MUST maintain a spin value for each network path and set the spin bit in the 1-RTT packet header to the currently stored value when sending on that path.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P4-0008")]
public sealed class REQ_QUIC_RFC9000_S17P4_0008
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P4-0008")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void LocalOneRttClose_SetsTheSpinBitToTheStoredActivePathValue()
    {
        using QuicConnectionRuntime runtime = QuicS17P4SpinBitTestSupport.CreateActiveOneRttRuntime(
            QuicTlsRole.Client);

        QuicS17P4SpinBitTestSupport.AssertLocalOneRttCloseSpinBit(
            runtime,
            expectedSpinBit: true,
            observedAtTicks: 10);
    }
}
