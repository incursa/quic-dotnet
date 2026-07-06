// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S4-1-P10-S1-R01">A sender MUST ignore any MAX_STREAM_DATA or MAX_DATA frames that do not increase flow control limits.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S4-1-P10-S1-R01")]
public sealed class RFC9000_S4_1_P10_S1_R01
{
    [Fact]
    [Requirement("RFC9000-S4-1-P10-S1-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryApplyMaxFlowControlFrames_AppliesIncreasingLimits()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionSendLimit: 8,
            peerBidirectionalSendLimit: 4,
            peerBidirectionalStreamLimit: 2,
            peerUnidirectionalStreamLimit: 2);

        Assert.True(state.TryApplyMaxDataFrame(new QuicMaxDataFrame(12)));
        Assert.Equal(12UL, state.ConnectionSendLimit);

        Assert.True(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(1, 10), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot streamSnapshot));
        Assert.Equal(10UL, streamSnapshot.SendLimit);
    }

    [Fact]
    [Requirement("RFC9000-S4-1-P10-S1-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryApplyMaxFlowControlFrames_IgnoresNonIncreasingLimits()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionSendLimit: 8,
            peerBidirectionalSendLimit: 4,
            peerBidirectionalStreamLimit: 2,
            peerUnidirectionalStreamLimit: 2);

        Assert.True(state.TryApplyMaxDataFrame(new QuicMaxDataFrame(12)));
        Assert.False(state.TryApplyMaxDataFrame(new QuicMaxDataFrame(12)));
        Assert.False(state.TryApplyMaxDataFrame(new QuicMaxDataFrame(11)));
        Assert.Equal(12UL, state.ConnectionSendLimit);

        Assert.True(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(1, 10), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.False(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(1, 10), out errorCode));
        Assert.Equal(default, errorCode);
        Assert.False(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(1, 9), out errorCode));
        Assert.Equal(default, errorCode);
    }

    [Fact]
    [Requirement("RFC9000-S4-1-P10-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void TryApplyMaxFlowControlFramesFuzz_IgnoresEveryNonIncreasingLimit()
    {
        (ulong InitialConnectionLimit, ulong[] ConnectionUpdates, ulong InitialStreamLimit, ulong[] StreamUpdates)[] cases =
        [
            (8, [12, 12, 11, 13, 10], 4, [10, 10, 9, 11, 8]),
            (0, [0, 1, 1, 2, 1], 0, [0, 1, 1, 2, 1]),
            (64, [65, 63, 66, 66, 67], 32, [33, 31, 34, 34, 35]),
        ];

        foreach ((ulong initialConnectionLimit, ulong[] connectionUpdates, ulong initialStreamLimit, ulong[] streamUpdates) in cases)
        {
            QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
                connectionSendLimit: initialConnectionLimit,
                peerBidirectionalSendLimit: initialStreamLimit,
                peerBidirectionalStreamLimit: 2,
                peerUnidirectionalStreamLimit: 2);
            ulong expectedConnectionLimit = initialConnectionLimit;
            ulong expectedStreamLimit = initialStreamLimit;

            foreach (ulong update in connectionUpdates)
            {
                bool applied = state.TryApplyMaxDataFrame(new QuicMaxDataFrame(update));

                Assert.Equal(update > expectedConnectionLimit, applied);
                expectedConnectionLimit = Math.Max(expectedConnectionLimit, update);
                Assert.Equal(expectedConnectionLimit, state.ConnectionSendLimit);
            }

            foreach (ulong update in streamUpdates)
            {
                bool applied = state.TryApplyMaxStreamDataFrame(
                    new QuicMaxStreamDataFrame(1, update),
                    out QuicTransportErrorCode errorCode);

                Assert.Equal(update > expectedStreamLimit, applied);
                Assert.Equal(default, errorCode);
                expectedStreamLimit = Math.Max(expectedStreamLimit, update);
                Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot streamSnapshot));
                Assert.Equal(expectedStreamLimit, streamSnapshot.SendLimit);
            }
        }
    }
}
