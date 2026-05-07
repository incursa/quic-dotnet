namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P4-0009">On receiving a 1-RTT packet that increases the highest packet number seen by the server from the client on a network path, the server MUST set the spin value for that path to be equal to the spin bit in the received packet.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P4-0009")]
public sealed class REQ_QUIC_RFC9000_S17P4_0009
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P4-0009")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerReceiveOneRttPacket_StoresTheReceivedSpinBitForThePath()
    {
        using QuicConnectionRuntime runtime = QuicS17P4SpinBitTestSupport.CreateActiveOneRttRuntime(
            QuicTlsRole.Server);

        QuicConnectionTransitionResult receiveResult = QuicS17P4SpinBitTestSupport.ReceivePeerPingPacket(
            runtime,
            spinBit: false,
            packetNumber: 0,
            observedAtTicks: 10);

        Assert.True(receiveResult.StateChanged);
        QuicS17P4SpinBitTestSupport.AssertLocalOneRttCloseSpinBit(
            runtime,
            expectedSpinBit: false,
            observedAtTicks: 11);
    }
}
