// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-19150007")]
public sealed class REQ_QUIC_RFC9000_19150007
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-19150007")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryAcceptNewConnectionId_IgnoresRetirePriorToThatDoesNotIncreaseTheLargestReceivedValue()
    {
        QuicConnectionPeerConnectionIdState state = new();
        byte[] initialDestinationConnectionId = [0x11, 0x12, 0x13, 0x14];
        byte[] firstConnectionId = [0x40, 0x41, 0x42];
        byte[] secondConnectionId = [0x60, 0x61, 0x62];
        byte[] staleConnectionId = [0x20, 0x21, 0x22];

        Assert.True(state.TryAcceptNewConnectionId(
            new QuicNewConnectionIdFrame(0x04, 0x03, firstConnectionId, QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0x50)),
            requiresZeroLengthDestinationConnectionId: false,
            activeConnectionIdLimit: 4UL,
            initialDestinationConnectionId: initialDestinationConnectionId,
            out QuicTransportErrorCode errorCode,
            out bool destinationConnectionIdChanged,
            out ulong[] retiredSequenceNumbers));
        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        Assert.True(destinationConnectionIdChanged);
        Assert.Equal([0UL], retiredSequenceNumbers);

        Assert.True(state.TryAcceptNewConnectionId(
            new QuicNewConnectionIdFrame(0x05, 0x02, secondConnectionId, QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0x70)),
            requiresZeroLengthDestinationConnectionId: false,
            activeConnectionIdLimit: 4UL,
            initialDestinationConnectionId: initialDestinationConnectionId,
            out errorCode,
            out destinationConnectionIdChanged,
            out retiredSequenceNumbers));
        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        Assert.False(destinationConnectionIdChanged);
        Assert.Empty(retiredSequenceNumbers);

        Assert.True(state.TryAcceptNewConnectionId(
            new QuicNewConnectionIdFrame(0x02, 0x00, staleConnectionId, QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0x30)),
            requiresZeroLengthDestinationConnectionId: false,
            activeConnectionIdLimit: 4UL,
            initialDestinationConnectionId: initialDestinationConnectionId,
            out errorCode,
            out destinationConnectionIdChanged,
            out retiredSequenceNumbers));
        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        Assert.False(destinationConnectionIdChanged);
        Assert.Equal([2UL], retiredSequenceNumbers);
        Assert.Equal(2, state.ActiveConnectionIdCount);
        Assert.Equal(0x04UL, state.CurrentDestinationConnectionIdSequence);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-19150007")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryAcceptNewConnectionId_DoesNotLowerTheRetirePriorToFloorWhenValueDecreases()
    {
        QuicConnectionPeerConnectionIdState state = new();
        byte[] initialDestinationConnectionId = [0x11, 0x12, 0x13, 0x14];
        byte[] firstConnectionId = [0x40, 0x41, 0x42];
        byte[] secondConnectionId = [0x60, 0x61, 0x62];
        byte[] staleConnectionId = [0x20, 0x21, 0x22];

        Assert.True(state.TryAcceptNewConnectionId(
            new QuicNewConnectionIdFrame(0x04, 0x03, firstConnectionId, QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0x50)),
            requiresZeroLengthDestinationConnectionId: false,
            activeConnectionIdLimit: 4UL,
            initialDestinationConnectionId: initialDestinationConnectionId,
            out QuicTransportErrorCode errorCode,
            out bool destinationConnectionIdChanged,
            out ulong[] retiredSequenceNumbers));
        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        Assert.True(destinationConnectionIdChanged);
        Assert.Equal([0UL], retiredSequenceNumbers);

        Assert.True(state.TryAcceptNewConnectionId(
            new QuicNewConnectionIdFrame(0x05, 0x01, secondConnectionId, QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0x70)),
            requiresZeroLengthDestinationConnectionId: false,
            activeConnectionIdLimit: 4UL,
            initialDestinationConnectionId: initialDestinationConnectionId,
            out errorCode,
            out destinationConnectionIdChanged,
            out retiredSequenceNumbers));
        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        Assert.False(destinationConnectionIdChanged);
        Assert.Empty(retiredSequenceNumbers);

        Assert.True(state.TryAcceptNewConnectionId(
            new QuicNewConnectionIdFrame(0x02, 0x00, staleConnectionId, QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0x30)),
            requiresZeroLengthDestinationConnectionId: false,
            activeConnectionIdLimit: 4UL,
            initialDestinationConnectionId: initialDestinationConnectionId,
            out errorCode,
            out destinationConnectionIdChanged,
            out retiredSequenceNumbers));
        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        Assert.False(destinationConnectionIdChanged);
        Assert.Equal([2UL], retiredSequenceNumbers);
        Assert.Equal(2, state.ActiveConnectionIdCount);
        Assert.Equal(0x04UL, state.CurrentDestinationConnectionIdSequence);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-19150007")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void TryAcceptNewConnectionId_FuzzDoesNotLowerLargestReceivedRetirePriorTo()
    {
        for (ulong highRetirePriorTo = 2; highRetirePriorTo <= 5; highRetirePriorTo++)
        {
            QuicConnectionPeerConnectionIdState state = new();
            byte[] initialDestinationConnectionId = [0x11, 0x12, 0x13, 0x14];
            ulong activeSequenceNumber = highRetirePriorTo + 1;

            Assert.True(state.TryAcceptNewConnectionId(
                new QuicNewConnectionIdFrame(
                    activeSequenceNumber,
                    highRetirePriorTo,
                    [unchecked((byte)(0x40 + highRetirePriorTo)), 0x41, 0x42],
                    QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(unchecked((byte)(0x50 + highRetirePriorTo)))),
                requiresZeroLengthDestinationConnectionId: false,
                activeConnectionIdLimit: 4UL,
                initialDestinationConnectionId: initialDestinationConnectionId,
                out QuicTransportErrorCode errorCode,
                out bool destinationConnectionIdChanged,
                out ulong[] retiredSequenceNumbers));
            Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
            Assert.True(destinationConnectionIdChanged);

            ulong staleSequenceNumber = highRetirePriorTo - 1;
            Assert.True(state.TryAcceptNewConnectionId(
                new QuicNewConnectionIdFrame(
                    staleSequenceNumber,
                    0x00,
                    [unchecked((byte)(0x20 + highRetirePriorTo)), 0x21, 0x22],
                    QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(unchecked((byte)(0x30 + highRetirePriorTo)))),
                requiresZeroLengthDestinationConnectionId: false,
                activeConnectionIdLimit: 4UL,
                initialDestinationConnectionId: initialDestinationConnectionId,
                out errorCode,
                out destinationConnectionIdChanged,
                out retiredSequenceNumbers));

            Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
            Assert.False(destinationConnectionIdChanged);
            Assert.Equal([staleSequenceNumber], retiredSequenceNumbers);
            Assert.Equal(activeSequenceNumber, state.CurrentDestinationConnectionIdSequence);
        }
    }
}
