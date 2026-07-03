// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="RFC9000-S17-4-P8-S1-R01">On receiving a 1-RTT packet that increases the highest packet number seen by the client from the server on a network path, the client MUST set the spin value for that path to the inverse of the spin bit in the received packet.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S17-4-P8-S1-R01")]
public sealed class REQ_QUIC_RFC9000_1098
{
    [Fact]
    [Requirement("RFC9000-S17-4-P8-S1-R01")]
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
    [Requirement("RFC9000-S17-4-P8-S1-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
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
