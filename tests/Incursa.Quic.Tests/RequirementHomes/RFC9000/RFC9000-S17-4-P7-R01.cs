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

    [Fact]
    [Requirement("RFC9000-S17-4-P7-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ServerReceiveOneRttPacketFuzz_StoresReceivedSpinBitOnlyForIncreasingPacketNumbers()
    {
        ((bool SpinBit, ulong PacketNumber, long ObservedAtTicks)[] Events, bool ExpectedLocalSpinBit)[] cases =
        [
            ([(false, 0, 10)], false),
            ([(false, 0, 10), (true, 1, 11)], true),
            ([(true, 2, 10), (false, 1, 11)], true),
            ([(false, 0, 10), (true, 2, 11), (false, 2, 12), (false, 3, 13)], false),
        ];

        foreach (((bool spinBit, ulong packetNumber, long observedAtTicks)[] events, bool expectedLocalSpinBit) in cases)
        {
            using QuicConnectionRuntime runtime = QuicS17P4SpinBitTestSupport.CreateActiveOneRttRuntime(
                QuicTlsRole.Server);

            foreach ((bool spinBit, ulong packetNumber, long observedAtTicks) in events)
            {
                _ = QuicS17P4SpinBitTestSupport.ReceivePeerPingPacket(
                    runtime,
                    spinBit,
                    packetNumber,
                    observedAtTicks);
            }

            QuicS17P4SpinBitTestSupport.AssertLocalOneRttCloseSpinBit(
                runtime,
                expectedLocalSpinBit,
                observedAtTicks: events[^1].observedAtTicks + 1);
        }
    }
}
