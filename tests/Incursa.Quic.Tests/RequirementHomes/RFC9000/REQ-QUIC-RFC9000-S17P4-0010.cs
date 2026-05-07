namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P4-0010">On receiving a 1-RTT packet that increases the highest packet number seen by the client from the server on a network path, the client MUST set the spin value for that path to the inverse of the spin bit in the received packet.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P4-0010")]
public sealed class REQ_QUIC_RFC9000_S17P4_0010
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P4-0010")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientReceiveOneRttPacket_StoresTheInverseOfTheReceivedSpinBitForThePath()
    {
        using QuicConnectionRuntime runtime = QuicS17P4SpinBitTestSupport.CreateActiveOneRttRuntime(
            QuicTlsRole.Client);

        QuicConnectionTransitionResult receiveResult = QuicS17P4SpinBitTestSupport.ReceivePeerPingPacket(
            runtime,
            spinBit: true,
            packetNumber: 0,
            observedAtTicks: 10);

        Assert.True(receiveResult.StateChanged);
        QuicS17P4SpinBitTestSupport.AssertLocalOneRttCloseSpinBit(
            runtime,
            expectedSpinBit: false,
            observedAtTicks: 11);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P4-0010")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ClientReceiveOneRttPacket_IgnoresNonIncreasingPacketNumbersForSpinUpdates()
    {
        using QuicConnectionRuntime runtime = QuicS17P4SpinBitTestSupport.CreateActiveOneRttRuntime(
            QuicTlsRole.Client);

        Assert.True(QuicS17P4SpinBitTestSupport.ReceivePeerPingPacket(
            runtime,
            spinBit: true,
            packetNumber: 1,
            observedAtTicks: 10).StateChanged);

        _ = QuicS17P4SpinBitTestSupport.ReceivePeerPingPacket(
            runtime,
            spinBit: false,
            packetNumber: 0,
            observedAtTicks: 11);

        QuicS17P4SpinBitTestSupport.AssertLocalOneRttCloseSpinBit(
            runtime,
            expectedSpinBit: false,
            observedAtTicks: 12);
    }
}
