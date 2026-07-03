// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S5-1-2-P6-S2-R01")]
public sealed class REQ_QUIC_RFC9000_S5P1P2_0013
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PeerConnectionIdState_AllowsTrackingTwiceTheActiveConnectionIdLimit()
    {
        QuicConnectionPeerConnectionIdState state = new();

        for (ulong sequenceNumber = 1; sequenceNumber <= 6; sequenceNumber++)
        {
            Assert.True(QuicConnectionIdLifecycleTestSupport.TryAcceptNewConnectionId(
                state,
                sequenceNumber,
                retirePriorTo: sequenceNumber,
                connectionIdStart: unchecked((byte)(0x40 + sequenceNumber)),
                activeConnectionIdLimit: 3UL,
                out QuicTransportErrorCode errorCode,
                out _,
                out _));
            Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        }

        Assert.Equal(6, state.PendingRetiredConnectionIdCount);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void PeerConnectionIdState_DoesNotAcceptMoreThanTwiceTheActiveConnectionIdLimit()
    {
        QuicConnectionPeerConnectionIdState state = new();

        for (ulong sequenceNumber = 1; sequenceNumber <= 6; sequenceNumber++)
        {
            Assert.True(QuicConnectionIdLifecycleTestSupport.TryAcceptNewConnectionId(
                state,
                sequenceNumber,
                retirePriorTo: sequenceNumber,
                connectionIdStart: unchecked((byte)(0x40 + sequenceNumber)),
                activeConnectionIdLimit: 3UL,
                out QuicTransportErrorCode errorCode,
                out _,
                out _));
            Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        }

        Assert.False(QuicConnectionIdLifecycleTestSupport.TryAcceptNewConnectionId(
            state,
            sequenceNumber: 7UL,
            retirePriorTo: 7UL,
            connectionIdStart: 0x47,
            activeConnectionIdLimit: 3UL,
            out QuicTransportErrorCode failureCode,
            out _,
            out _));

        Assert.Equal(QuicTransportErrorCode.ConnectionIdLimitError, failureCode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void PeerConnectionIdState_AllowsExactlyTwiceTheMinimumActiveConnectionIdLimit()
    {
        QuicConnectionPeerConnectionIdState state = new();

        for (ulong sequenceNumber = 1; sequenceNumber <= 4; sequenceNumber++)
        {
            Assert.True(QuicConnectionIdLifecycleTestSupport.TryAcceptNewConnectionId(
                state,
                sequenceNumber,
                retirePriorTo: sequenceNumber,
                connectionIdStart: unchecked((byte)(0x50 + sequenceNumber)),
                activeConnectionIdLimit: 2UL,
                out QuicTransportErrorCode errorCode,
                out _,
                out _));
            Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        }

        Assert.Equal(4, state.PendingRetiredConnectionIdCount);
    }

}
