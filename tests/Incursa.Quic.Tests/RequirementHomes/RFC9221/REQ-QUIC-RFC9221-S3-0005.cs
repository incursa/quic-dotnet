// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9221-S3-0005">An endpoint MUST NOT send a DATAGRAM frame larger than the max_datagram_frame_size value it received from its peer.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9221-S3-0005")]
public sealed class REQ_QUIC_RFC9221_S3_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task SendDatagramAsync_SendsFrameWithinPeerLimit()
    {
        QuicConnectionRuntime runtime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
            localMaxDatagramFrameSize: 1200,
            peerMaxDatagramFrameSize: 1200);

        QuicDatagramSendResult result = await QuicDatagramRuntimeTestSupport.SendDatagramAsync(
            runtime,
            new byte[] { 0xD1, 0xD2 });

        Assert.NotNull(result.SendEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task SendDatagramAsync_RejectsFramesLargerThanPeerLimit()
    {
        QuicConnectionRuntime runtime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
            localMaxDatagramFrameSize: 1200,
            peerMaxDatagramFrameSize: 3);
        int sentPacketCount = runtime.SendRuntime.SentPackets.Count;

        InvalidOperationException exception = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await QuicDatagramRuntimeTestSupport.SendDatagramAsync(
                runtime,
                new byte[] { 0xD1, 0xD2 }));

        Assert.Contains("exceeds the peer max_datagram_frame_size", exception.Message, StringComparison.Ordinal);
        Assert.Equal(sentPacketCount, runtime.SendRuntime.SentPackets.Count);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public async Task SendDatagramAsync_SendsFrameExactlyAtPeerLimit()
    {
        QuicConnectionRuntime runtime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
            localMaxDatagramFrameSize: 1200,
            peerMaxDatagramFrameSize: 4);

        QuicDatagramSendResult result = await QuicDatagramRuntimeTestSupport.SendDatagramAsync(
            runtime,
            new byte[] { 0xD1, 0xD2 });

        Assert.NotNull(result.SendEffect);
        QuicDatagramFrame frame = QuicDatagramRuntimeTestSupport.ParseFirstOutgoingDatagramFrame(
            runtime,
            result.SendEffect);
        Assert.Equal([0xD1, 0xD2], frame.DatagramData);
    }
}
