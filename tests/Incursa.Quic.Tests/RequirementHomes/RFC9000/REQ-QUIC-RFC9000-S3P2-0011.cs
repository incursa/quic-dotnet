using FsCheck.Xunit;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S3P2-0011">An endpoint MUST open lower-numbered peer streams first.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S3P2-0011")]
public sealed class REQ_QUIC_RFC9000_S3P2_0011
{
    [Property]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0011")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Property")]
    public void TryApplyMaxStreamDataFrame_OpensLowerNumberedPeerStreamsFirst(byte streamIndex)
    {
        QuicConnectionStreamState state = CreatePeerStreamState();

        ulong streamOrdinal = streamIndex;
        ulong streamId = (streamOrdinal << 2) | 1UL;

        Assert.True(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(streamId, 16), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        AssertLowerNumberedPeerStreamsAreOpened(state, streamOrdinal);
        AssertHigherNumberedPeerStreamIsNotOpened(state, streamOrdinal);
    }

    [Property]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0011")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Property")]
    public void TryReceiveStopSendingFrame_OpensLowerNumberedPeerStreamsFirst(byte streamIndex)
    {
        QuicConnectionStreamState state = CreatePeerStreamState();

        ulong streamOrdinal = streamIndex;
        ulong streamId = (streamOrdinal << 2) | 1UL;

        Assert.True(state.TryReceiveStopSendingFrame(
            new QuicStopSendingFrame(streamId, 0x99),
            out QuicResetStreamFrame resetStreamFrame,
            out QuicTransportErrorCode errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(streamId, resetStreamFrame.StreamId);
        Assert.Equal(0x99UL, resetStreamFrame.ApplicationProtocolErrorCode);
        Assert.Equal(0UL, resetStreamFrame.FinalSize);

        AssertLowerNumberedPeerStreamsAreOpened(state, streamOrdinal);
        AssertHigherNumberedPeerStreamIsNotOpened(state, streamOrdinal);
    }

    private static QuicConnectionStreamState CreatePeerStreamState()
    {
        return QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 128,
            connectionSendLimit: 128,
            incomingBidirectionalStreamLimit: 1024,
            incomingUnidirectionalStreamLimit: 1024,
            peerBidirectionalStreamLimit: 1024,
            peerUnidirectionalStreamLimit: 1024,
            peerBidirectionalReceiveLimit: 32,
            peerUnidirectionalReceiveLimit: 32,
            localBidirectionalReceiveLimit: 32,
            localUnidirectionalSendLimit: 32,
            peerBidirectionalSendLimit: 8);
    }

    private static void AssertLowerNumberedPeerStreamsAreOpened(QuicConnectionStreamState state, ulong streamOrdinal)
    {
        for (ulong index = 0; index <= streamOrdinal; index++)
        {
            ulong knownStreamId = (index << 2) | 1UL;
            Assert.True(state.TryGetStreamSnapshot(knownStreamId, out QuicConnectionStreamSnapshot _));
        }
    }

    private static void AssertHigherNumberedPeerStreamIsNotOpened(QuicConnectionStreamState state, ulong streamOrdinal)
    {
        ulong higherStreamId = ((streamOrdinal + 1UL) << 2) | 1UL;
        Assert.False(state.TryGetStreamSnapshot(higherStreamId, out _));
    }
}
