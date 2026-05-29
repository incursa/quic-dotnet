// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9221-S5P3-0001">DATAGRAM frame payload bytes MUST NOT contribute to stream-level or connection-level data flow-control accounting.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9221-S5P3-0001")]
public sealed class REQ_QUIC_RFC9221_S5P3_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task SendDatagramAsync_DoesNotAssociatePacketWithStreamFlowControl()
    {
        QuicConnectionRuntime runtime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
            localMaxDatagramFrameSize: 1200,
            peerMaxDatagramFrameSize: 1200);

        QuicDatagramSendResult result = await QuicDatagramRuntimeTestSupport.SendDatagramAsync(
            runtime,
            new byte[] { 0xD1, 0xD2, 0xD3 });

        Assert.NotNull(result.SendEffect);
        Assert.NotNull(result.TrackedPacket);
        Assert.Null(result.TrackedPacket.Value.StreamIds);

        QuicDatagramFrame frame = QuicDatagramRuntimeTestSupport.ParseFirstOutgoingDatagramFrame(
            runtime,
            result.SendEffect);
        Assert.Equal([0xD1, 0xD2, 0xD3], frame.DatagramData.ToArray());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task SendDatagramAsync_DoesNotConsumeConnectionFlowControlCredit()
    {
        QuicConnectionRuntime runtime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
            localMaxDatagramFrameSize: 1200,
            peerMaxDatagramFrameSize: 1200,
            connectionSendLimit: 1);

        QuicDatagramSendResult result = await QuicDatagramRuntimeTestSupport.SendDatagramAsync(
            runtime,
            new byte[] { 0xD1, 0xD2, 0xD3 });

        Assert.NotNull(result.SendEffect);
        Assert.Null(runtime.TerminalState);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public async Task SendDatagramAsync_DoesNotConsumeAnyStreamSendCredit()
    {
        QuicConnectionRuntime runtime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
            localMaxDatagramFrameSize: 1200,
            peerMaxDatagramFrameSize: 1200,
            localBidirectionalSendLimit: 0);

        QuicDatagramSendResult result = await QuicDatagramRuntimeTestSupport.SendDatagramAsync(
            runtime,
            new byte[] { 0xD1 });

        Assert.NotNull(result.SendEffect);
        Assert.Null(result.TrackedPacket!.Value.StreamIds);
    }
}
