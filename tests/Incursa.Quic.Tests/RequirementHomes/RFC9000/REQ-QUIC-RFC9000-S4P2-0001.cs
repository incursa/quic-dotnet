namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P2-0001">A receiver MAY send a MAX_STREAM_DATA or MAX_DATA frame multiple times within a round trip or send it early enough to allow time for loss of the frame and subsequent recovery.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S4P2-0001")]
public sealed class REQ_QUIC_RFC9000_S4P2_0001
{
    private const ulong MaximumFlowControlLimit = QuicVariableLengthInteger.MaxValue;

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P2-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryApplyMaxFrames_AllowsRepeatedCreditAdvertisements()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionSendLimit: 8,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(state.TryApplyMaxDataFrame(new QuicMaxDataFrame(12)));
        Assert.True(state.TryApplyMaxDataFrame(new QuicMaxDataFrame(16)));
        Assert.False(state.TryApplyMaxDataFrame(new QuicMaxDataFrame(15)));
        Assert.Equal(16UL, state.ConnectionSendLimit);

        Assert.True(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(1, 10), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.True(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(1, 14), out errorCode));
        Assert.Equal(default, errorCode);
        Assert.False(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(1, 13), out errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(14UL, snapshot.SendLimit);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P2-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryApplyMaxFrames_IgnoresRepeatedCreditAdvertisementsThatDoNotIncreaseTheLimit()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionSendLimit: 8,
            peerBidirectionalReceiveLimit: 8);

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

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(10UL, snapshot.SendLimit);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P2-0001")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryApplyMaxFrames_AllowsMaximumRepresentableCreditAdvertisements()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionSendLimit: MaximumFlowControlLimit - 1,
            peerBidirectionalReceiveLimit: MaximumFlowControlLimit - 1);

        Assert.True(state.TryApplyMaxDataFrame(new QuicMaxDataFrame(MaximumFlowControlLimit)));
        Assert.False(state.TryApplyMaxDataFrame(new QuicMaxDataFrame(MaximumFlowControlLimit)));
        Assert.Equal(MaximumFlowControlLimit, state.ConnectionSendLimit);

        Assert.True(state.TryApplyMaxStreamDataFrame(
            new QuicMaxStreamDataFrame(1, MaximumFlowControlLimit),
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.False(state.TryApplyMaxStreamDataFrame(
            new QuicMaxStreamDataFrame(1, MaximumFlowControlLimit),
            out errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(MaximumFlowControlLimit, snapshot.SendLimit);
    }
}
