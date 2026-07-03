// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S11-2-P2-S2-R01">RESET_STREAM MUST only be instigated by the application protocol that uses QUIC.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S11-2-P2-S2-R01")]
public sealed class REQ_QUIC_RFC9000_S11P2_0002
{
    [Fact]
    [Requirement("RFC9000-S11-2-P2-S2-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryAbortLocalStreamWrites_UsesTheApplicationProtocolOwnedResetPath()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState();

        Assert.True(state.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.True(state.TryAbortLocalStreamWrites(
            streamId.Value,
            out ulong finalSize,
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(0UL, finalSize);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamType.Bidirectional, snapshot.StreamType);
        Assert.Equal(QuicStreamSendState.ResetSent, snapshot.SendState);
        Assert.Equal(QuicStreamReceiveState.Recv, snapshot.ReceiveState);
        Assert.True(snapshot.HasFinalSize);
        Assert.Equal(0UL, snapshot.FinalSize);
    }

    [Fact]
    [Requirement("RFC9000-S11-2-P2-S2-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryAbortLocalStreamWrites_RejectsPeerInitiatedStreams()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState();

        Assert.False(state.TryAbortLocalStreamWrites(
            1,
            out ulong finalSize,
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, finalSize);
        Assert.Equal(QuicTransportErrorCode.StreamStateError, errorCode);
    }
}
