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

    [Fact]
    [Requirement("RFC9000-S17-4-P8-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ClientReceiveOneRttPacketFuzz_StoresInverseSpinBitOnlyForIncreasingPacketNumbers()
    {
        ((bool SpinBit, ulong PacketNumber, long ObservedAtTicks)[] Events, bool ExpectedLocalSpinBit)[] cases =
        [
            ([(true, 0, 10)], false),
            ([(true, 0, 10), (false, 1, 11)], true),
            ([(false, 2, 10), (true, 1, 11)], true),
            ([(true, 0, 10), (false, 2, 11), (true, 2, 12), (true, 3, 13)], false),
        ];

        foreach (((bool spinBit, ulong packetNumber, long observedAtTicks)[] events, bool expectedLocalSpinBit) in cases)
        {
            using QuicConnectionRuntime runtime = QuicS17P4SpinBitTestSupport.CreateActiveOneRttRuntime(
                QuicTlsRole.Client);

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
