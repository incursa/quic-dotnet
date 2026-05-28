// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9221-S5P4-0002">When congestion control prevents sending, an endpoint MUST either delay or drop DATAGRAM frames without treating the condition as a transport error.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9221-S5P4-0002")]
public sealed class REQ_QUIC_RFC9221_S5P4_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task SendDatagramAsync_DropsWhenCongestionWindowIsExhausted()
    {
        QuicConnectionRuntime runtime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
            localMaxDatagramFrameSize: 1200,
            peerMaxDatagramFrameSize: 1200,
            connectionSendLimit: 64 * 1024);
        byte[] datagramData = Enumerable.Repeat((byte)0xD1, 1000).ToArray();
        int sentCount = 0;

        for (int attempt = 0; attempt < 64; attempt++)
        {
            int trackedPacketCountBefore = runtime.SendRuntime.SentPackets.Count;
            QuicDatagramSendResult result = await QuicDatagramRuntimeTestSupport.SendDatagramAsync(
                runtime,
                datagramData);

            if (result.SendEffect is null)
            {
                Assert.True(sentCount > 0);
                Assert.Null(runtime.TerminalState);
                Assert.Equal(trackedPacketCountBefore, runtime.SendRuntime.SentPackets.Count);
                return;
            }

            sentCount++;
        }

        Assert.Fail("Expected congestion control to drop a DATAGRAM before the bounded send loop completed.");
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public async Task SendDatagramAsync_CompletesWithoutTransportErrorWhenCongestionBlocksDatagram()
    {
        QuicConnectionRuntime runtime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
            localMaxDatagramFrameSize: 1200,
            peerMaxDatagramFrameSize: 1200,
            connectionSendLimit: 64 * 1024);
        byte[] datagramData = Enumerable.Repeat((byte)0xD1, 1000).ToArray();

        for (int attempt = 0; attempt < 64; attempt++)
        {
            QuicDatagramSendResult result = await QuicDatagramRuntimeTestSupport.SendDatagramAsync(
                runtime,
                datagramData);

            if (result.SendEffect is null)
            {
                Assert.Null(runtime.TerminalState);
                return;
            }
        }

        Assert.Fail("Expected congestion blocking to drop the DATAGRAM without a terminal transport error.");
    }
}
