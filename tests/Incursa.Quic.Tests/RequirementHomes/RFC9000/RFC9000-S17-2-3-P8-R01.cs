// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S17-2-3-P8-R01">A server SHOULD treat a violation of remembered limits (Section 7.4.1) as a connection error of an appropriate type (for instance, a FLOW_CONTROL_ERROR for exceeding stream data limits).</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S17-2-3-P8-R01")]
public sealed class RFC9000_S17_2_3_P8_R01
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReceiveStreamFrame_ReportsAConnectionErrorForRememberedLimitViolations()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            peerBidirectionalReceiveLimit: 3,
            connectionReceiveLimit: 3);

        byte[] initialPacket = QuicStreamTestData.BuildStreamFrame(0x0E, streamId: 1, streamData: [0x10, 0x11], offset: 0);
        Assert.True(QuicStreamParser.TryParseStreamFrame(initialPacket, out QuicStreamFrame initialFrame));
        Assert.True(state.TryReceiveStreamFrame(initialFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        byte[] rememberedLimitViolationPacket = QuicStreamTestData.BuildStreamFrame(
            0x0E,
            streamId: 1,
            streamData: [0x12, 0x13],
            offset: 2);
        Assert.True(QuicStreamParser.TryParseStreamFrame(rememberedLimitViolationPacket, out QuicStreamFrame violationFrame));
        Assert.False(state.TryReceiveStreamFrame(violationFrame, out errorCode));
        Assert.Equal(QuicTransportErrorCode.FlowControlError, errorCode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReceiveStreamFrame_AllowsDataWithinRememberedLimits()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            peerBidirectionalReceiveLimit: 4,
            connectionReceiveLimit: 4);

        byte[] frameBytes = QuicStreamTestData.BuildStreamFrame(
            0x0E,
            streamId: 1,
            streamData: [0x10, 0x11, 0x12, 0x13],
            offset: 0);

        Assert.True(QuicStreamParser.TryParseStreamFrame(frameBytes, out QuicStreamFrame frame));
        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
    }
}
