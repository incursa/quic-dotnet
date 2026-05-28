// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0221")]
public sealed class REQ_QUIC_RFC9000_0221
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PreferredAddressConnectionIdIsRetiredAsSequenceNumberOne()
    {
        QuicConnectionPeerConnectionIdState state = new();
        QuicPreferredAddress preferredAddress = QuicPreferredAddressRequirementTestSupport.CreatePreferredAddress(
            preferredConnectionId: [0x20, 0x21, 0x22]);

        Assert.True(state.TryAcceptPreferredAddressConnectionId(
            preferredAddress,
            activeConnectionIdLimit: 2UL,
            initialDestinationConnectionId: [0x01, 0x02, 0x03],
            out QuicTransportErrorCode errorCode,
            out bool destinationConnectionIdChanged));
        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        Assert.False(destinationConnectionIdChanged);

        Assert.True(state.TryAcceptNewConnectionId(
            new QuicNewConnectionIdFrame(
                2UL,
                2UL,
                [0x30, 0x31, 0x32],
                QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0x30)),
            requiresZeroLengthDestinationConnectionId: false,
            activeConnectionIdLimit: 2UL,
            initialDestinationConnectionId: [0x01, 0x02, 0x03],
            out errorCode,
            out destinationConnectionIdChanged,
            out ulong[] retiredSequenceNumbers));

        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        Assert.True(destinationConnectionIdChanged);
        Assert.Equal([0UL, 1UL], retiredSequenceNumbers);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void PreferredAddressConnectionIdCannotBeReusedUnderADifferentSequenceNumber()
    {
        QuicConnectionPeerConnectionIdState state = new();
        byte[] preferredConnectionId = [0x40, 0x41, 0x42];
        QuicPreferredAddress preferredAddress = QuicPreferredAddressRequirementTestSupport.CreatePreferredAddress(
            preferredConnectionId: preferredConnectionId);

        Assert.True(state.TryAcceptPreferredAddressConnectionId(
            preferredAddress,
            activeConnectionIdLimit: 2UL,
            initialDestinationConnectionId: [0x01, 0x02, 0x03],
            out QuicTransportErrorCode errorCode,
            out _));

        Assert.False(state.TryAcceptNewConnectionId(
            new QuicNewConnectionIdFrame(
                2UL,
                0UL,
                preferredConnectionId,
                QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0x50)),
            requiresZeroLengthDestinationConnectionId: false,
            activeConnectionIdLimit: 2UL,
            initialDestinationConnectionId: [0x01, 0x02, 0x03],
            out errorCode,
            out bool destinationConnectionIdChanged,
            out ulong[] retiredSequenceNumbers));

        Assert.Equal(QuicTransportErrorCode.ProtocolViolation, errorCode);
        Assert.False(destinationConnectionIdChanged);
        Assert.Empty(retiredSequenceNumbers);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void DuplicatePreferredAddressConnectionIdKeepsTheImplicitSequenceNumberStable()
    {
        QuicConnectionPeerConnectionIdState state = new();
        QuicPreferredAddress preferredAddress = QuicPreferredAddressRequirementTestSupport.CreatePreferredAddress(
            preferredConnectionId: [0x60, 0x61, 0x62]);

        Assert.True(state.TryAcceptPreferredAddressConnectionId(
            preferredAddress,
            activeConnectionIdLimit: 2UL,
            initialDestinationConnectionId: [0x01, 0x02, 0x03],
            out QuicTransportErrorCode errorCode,
            out bool destinationConnectionIdChanged));
        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        Assert.False(destinationConnectionIdChanged);

        Assert.True(state.TryAcceptPreferredAddressConnectionId(
            preferredAddress,
            activeConnectionIdLimit: 2UL,
            initialDestinationConnectionId: [0x01, 0x02, 0x03],
            out errorCode,
            out destinationConnectionIdChanged));

        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        Assert.False(destinationConnectionIdChanged);
        Assert.Equal(2, state.ActiveConnectionIdCount);
    }
}
