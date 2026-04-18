namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P12-0001">A sender SHOULD send a DATA_BLOCKED frame (type=0x14) when it wishes to send data but is unable to do so due to connection-level flow control; see Section 4.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S19P12-0001")]
public sealed class REQ_QUIC_RFC9000_S19P12_0001
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P12-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReserveSendCapacity_ReturnsDataBlockedFrameWhenConnectionCreditIsExhausted()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionSendLimit: 1,
            localBidirectionalSendLimit: 8);

        Assert.True(state.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.False(state.TryReserveSendCapacity(
            streamId.Value,
            offset: 0,
            length: 2,
            fin: false,
            out QuicDataBlockedFrame dataBlockedFrame,
            out QuicStreamDataBlockedFrame streamDataBlockedFrame,
            out QuicTransportErrorCode errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(1UL, dataBlockedFrame.MaximumData);
        Assert.Equal(default, streamDataBlockedFrame);
    }
}
