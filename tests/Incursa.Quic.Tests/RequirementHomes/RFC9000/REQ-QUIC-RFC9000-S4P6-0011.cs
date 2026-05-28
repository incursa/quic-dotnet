// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P6-0011">MAX_STREAMS frames that do not increase the stream limit MUST be ignored.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S4P6-0011")]
public sealed class REQ_QUIC_RFC9000_S4P6_0011
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    [Requirement("REQ-QUIC-RFC9000-S4P6-0011")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryApplyMaxStreamsFrame_IgnoresEqualLimits(bool bidirectional)
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            peerBidirectionalStreamLimit: bidirectional ? 2UL : 4UL,
            peerUnidirectionalStreamLimit: bidirectional ? 4UL : 2UL);

        Assert.False(state.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(bidirectional, 2)));

        Assert.Equal(bidirectional ? 2UL : 4UL, state.PeerBidirectionalStreamLimit);
        Assert.Equal(bidirectional ? 4UL : 2UL, state.PeerUnidirectionalStreamLimit);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P6-0011")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryApplyMaxStreamsFrame_IgnoresRepeatedUnidirectionalLimit()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            peerBidirectionalStreamLimit: 2,
            peerUnidirectionalStreamLimit: 2);

        Assert.True(state.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(false, 4)));
        Assert.Equal(4UL, state.PeerUnidirectionalStreamLimit);

        Assert.False(state.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(false, 4)));
        Assert.Equal(4UL, state.PeerUnidirectionalStreamLimit);
    }
}
