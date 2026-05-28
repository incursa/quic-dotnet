// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S18P2-0034")]
public sealed class REQ_QUIC_RFC9000_S18P2_0034
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryAcceptNewConnectionId_CountsHandshakeAndPreferredAddressConnectionIdsAgainstTheActiveLimit()
    {
        byte[] initialSourceConnectionId = QuicPreferredAddressRequirementTestSupport.InitialSourceConnectionId;
        QuicConnectionPeerConnectionIdState state = new();
        Assert.True(state.TryAcceptPreferredAddressConnectionId(
            QuicPreferredAddressRequirementTestSupport.CreatePreferredAddress(),
            activeConnectionIdLimit: 2UL,
            initialDestinationConnectionId: initialSourceConnectionId,
            out QuicTransportErrorCode errorCode,
            out _));
        Assert.Equal(2, state.ActiveConnectionIdCount);

        Assert.False(state.TryAcceptNewConnectionId(
            new QuicNewConnectionIdFrame(
                sequenceNumber: 2,
                retirePriorTo: 0,
                connectionId: [0x40, 0x41, 0x42, 0x43],
                statelessResetToken: [0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F]),
            requiresZeroLengthDestinationConnectionId: false,
            activeConnectionIdLimit: 2UL,
            initialDestinationConnectionId: initialSourceConnectionId,
            out errorCode,
            out _,
            out _));

        Assert.Equal(QuicTransportErrorCode.ConnectionIdLimitError, errorCode);
    }
}
