// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9221-S5P4-0001">DATAGRAM frames MUST be congestion controlled.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9221-S5P4-0001")]
public sealed class REQ_QUIC_RFC9221_S5P4_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task SendDatagramAsync_AccountsProtectedPacketInCongestionState()
    {
        QuicConnectionRuntime runtime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
            localMaxDatagramFrameSize: 1200,
            peerMaxDatagramFrameSize: 1200);
        ulong bytesInFlightBefore =
            runtime.SendRuntime.FlowController.CongestionControlState.BytesInFlightBytes;

        QuicDatagramSendResult result = await QuicDatagramRuntimeTestSupport.SendDatagramAsync(
            runtime,
            new byte[] { 0xD1, 0xD2, 0xD3 });

        Assert.NotNull(result.SendEffect);
        Assert.NotNull(result.TrackedPacket);
        Assert.Equal((ulong)result.SendEffect.Datagram.Length, result.TrackedPacket.Value.PayloadBytes);
        Assert.True(
            runtime.SendRuntime.FlowController.CongestionControlState.BytesInFlightBytes
            >= bytesInFlightBefore + result.TrackedPacket.Value.PayloadBytes);
    }
}
