// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="RFC9000-S17-4-P7-R01">On receiving a 1-RTT packet that increases the highest packet number seen by the server from the client on a network path, the server MUST set the spin value for that path to be equal to the spin bit in the received packet.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S17-4-P7-R01")]
public sealed class RFC9000_S17_4_P7_R01
{
    [Fact]
    [Requirement("RFC9000-S17-4-P7-R01")]
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
