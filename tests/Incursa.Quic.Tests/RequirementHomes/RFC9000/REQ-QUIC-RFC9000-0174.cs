namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0174">A sender MUST ignore any MAX_STREAM_DATA or MAX_DATA frames that do not increase flow control limits.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-0174")]
public sealed class REQ_QUIC_RFC9000_0174
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0174")]
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
    [Requirement("REQ-QUIC-RFC9000-0174")]
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
}
