// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0168">A MAX_STREAM_DATA frame MUST indicate the maximum absolute byte offset of a stream.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-0168")]
public sealed class REQ_QUIC_RFC9000_0168
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryApplyMaxStreamDataFrame_UsesAbsoluteStreamOffset()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionSendLimit: 16,
            peerBidirectionalSendLimit: 8,
            peerBidirectionalStreamLimit: 2,
            peerUnidirectionalStreamLimit: 2);

        Assert.True(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(1, 10), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(10UL, snapshot.SendLimit);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryApplyMaxStreamDataFrame_IgnoresMaximumStreamDataThatDoesNotIncreaseTheLimit()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionSendLimit: 16,
            peerBidirectionalSendLimit: 8,
            peerBidirectionalStreamLimit: 2,
            peerUnidirectionalStreamLimit: 2);

        Assert.True(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(1, 10), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.False(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(1, 9), out errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(10UL, snapshot.SendLimit);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryApplyMaxStreamDataFrame_AcceptsTheMaximumVarintStreamOffset()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionSendLimit: 16,
            peerBidirectionalSendLimit: 8,
            peerBidirectionalStreamLimit: 2,
            peerUnidirectionalStreamLimit: 2);

        Assert.True(state.TryApplyMaxStreamDataFrame(
            new QuicMaxStreamDataFrame(1, QuicVariableLengthInteger.MaxValue),
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicVariableLengthInteger.MaxValue, snapshot.SendLimit);
    }
}
