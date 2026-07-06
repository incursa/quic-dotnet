// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S4-6-P6-S2-R01">An endpoint MUST NOT wait to receive STREAMS_BLOCKED before advertising additional credit.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S4-6-P6-S2-R01")]
public sealed class REQ_QUIC_RFC9000_0204
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryPeekPeerStreamCapacityRelease_OffersMoreUnidirectionalCreditAfterThePeerStreamCloses()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            incomingUnidirectionalStreamLimit: 1);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0B, streamId: 3, streamData: []),
            out QuicStreamFrame frame));
        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryPeekPeerStreamCapacityRelease(3, out QuicMaxStreamsFrame releaseFrame));
        Assert.False(releaseFrame.IsBidirectional);
        Assert.Equal(2UL, releaseFrame.MaximumStreams);

        Assert.True(state.TryCommitPeerStreamCapacityRelease(3, releaseFrame));
        Assert.Equal(2UL, state.IncomingUnidirectionalStreamLimit);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryPeekPeerStreamCapacityRelease_ReturnsFalseWhileThePeerStreamIsStillOpen()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            incomingUnidirectionalStreamLimit: 1);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0A, streamId: 3, streamData: [0x51]),
            out QuicStreamFrame frame));
        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.False(state.TryPeekPeerStreamCapacityRelease(3, out _));
    }

    [Fact]
    [Requirement("RFC9000-S4-6-P6-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TryPeekPeerStreamCapacityRelease_AdvertisesCreditAsSoonAsPeerStreamsClose()
    {
        foreach ((bool Bidirectional, ulong PeerStreamId) testCase in new (bool, ulong)[]
        {
            (true, 1UL),
            (false, 3UL),
        })
        {
            for (int streamLimit = 1; streamLimit <= 4; streamLimit++)
            {
                QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
                    incomingBidirectionalStreamLimit: testCase.Bidirectional ? (ulong)streamLimit : 8UL,
                    incomingUnidirectionalStreamLimit: testCase.Bidirectional ? 8UL : (ulong)streamLimit);

                Assert.True(QuicStreamParser.TryParseStreamFrame(
                    QuicStreamTestData.BuildStreamFrame(0x0B, testCase.PeerStreamId, streamData: []),
                    out QuicStreamFrame frame));
                Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
                Assert.Equal(default, errorCode);
                if (testCase.Bidirectional)
                {
                    Assert.True(state.TryAbortLocalStreamWrites(testCase.PeerStreamId, out ulong finalSize, out errorCode));
                    Assert.Equal(default, errorCode);
                    Assert.Equal(0UL, finalSize);
                }

                Assert.True(state.TryPeekPeerStreamCapacityRelease(testCase.PeerStreamId, out QuicMaxStreamsFrame releaseFrame));
                Assert.Equal(testCase.Bidirectional, releaseFrame.IsBidirectional);
                Assert.Equal((ulong)(streamLimit + 1), releaseFrame.MaximumStreams);

                Assert.True(state.TryCommitPeerStreamCapacityRelease(testCase.PeerStreamId, releaseFrame));
                Assert.Equal(
                    (ulong)(streamLimit + 1),
                    testCase.Bidirectional ? state.IncomingBidirectionalStreamLimit : state.IncomingUnidirectionalStreamLimit);
            }
        }
    }
}
