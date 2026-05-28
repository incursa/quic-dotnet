// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class QuicConnectionIssuedConnectionIdStateTests
{
    [Fact]
    public void TryRegisterIssuedConnectionId_TracksStateAndStoresInputs()
    {
        QuicConnectionIssuedConnectionIdState state = new();
        byte[] connectionIdBytes = [0x10, 0x11, 0x12];
        byte[] statelessResetToken = CreateStatelessResetToken(0x20);

        Assert.True(state.CanIssueAnotherConnectionId(1));
        Assert.True(state.TryRegisterIssuedConnectionId(
            4,
            connectionIdBytes,
            statelessResetToken,
            peerActiveConnectionIdLimit: 8));

        Assert.Same(connectionIdBytes, state.IssuedConnectionIdBytesByConnectionId[4]);
        Assert.Same(statelessResetToken, state.StatelessResetTokensByConnectionId[4]);
        Assert.Single(state.StatelessResetTokensByConnectionId);
        Assert.Equal(4UL, state.HighestConnectionIdIssuedToPeer);
        Assert.Equal(1UL, state.TotalIssuedConnectionIdCount);
        Assert.False(state.CanIssueAnotherConnectionId(1));
        Assert.True(state.CanIssueAnotherConnectionId(2));
    }

    [Fact]
    public void TryRegisterIssuedConnectionId_RejectsDuplicateBytesAndPeerCapacityLimit()
    {
        QuicConnectionIssuedConnectionIdState state = new();
        byte[] connectionIdBytes = [0x20, 0x21, 0x22];
        byte[] firstToken = CreateStatelessResetToken(0x30);
        byte[] secondToken = CreateStatelessResetToken(0x40);

        Assert.True(state.TryRegisterIssuedConnectionId(
            1,
            connectionIdBytes,
            firstToken,
            peerActiveConnectionIdLimit: 8));

        Assert.False(state.TryRegisterIssuedConnectionId(
            2,
            connectionIdBytes,
            secondToken,
            peerActiveConnectionIdLimit: 8));

        Assert.False(state.TryRegisterIssuedConnectionId(
            2,
            [0x23, 0x24, 0x25],
            secondToken,
            peerActiveConnectionIdLimit: 2));
    }

    [Fact]
    public void TryRetireIssuedConnectionId_AndMarkIssuedConnectionIdUsed_UpdateTrackedState()
    {
        QuicConnectionIssuedConnectionIdState state = new();
        byte[] connectionIdBytes = [0x30, 0x31, 0x32];
        byte[] statelessResetToken = CreateStatelessResetToken(0x50);

        Assert.True(state.TryRegisterIssuedConnectionId(
            3,
            connectionIdBytes,
            statelessResetToken,
            peerActiveConnectionIdLimit: 8));

        Assert.True(state.TryMarkIssuedConnectionIdUsed(3));
        Assert.False(state.TryMarkIssuedConnectionIdUsed(3));

        Assert.True(state.TryRetireIssuedConnectionId(3, out byte[]? retiredConnectionIdBytes));
        Assert.Equal(connectionIdBytes, retiredConnectionIdBytes);
        Assert.False(state.TryRetireIssuedConnectionId(3, out _));
        Assert.False(state.TryMarkIssuedConnectionIdUsed(3));
        Assert.Empty(state.StatelessResetTokensByConnectionId);
    }

    [Fact]
    public void TryRegisterIssuedConnectionId_AllowsEntriesWithoutRouteBytes()
    {
        QuicConnectionIssuedConnectionIdState state = new();
        byte[] statelessResetToken = CreateStatelessResetToken(0x60);

        Assert.True(state.TryRegisterIssuedConnectionId(
            9,
            null,
            statelessResetToken,
            peerActiveConnectionIdLimit: 8));

        Assert.False(state.IssuedConnectionIdBytesByConnectionId.ContainsKey(9));
        Assert.Same(statelessResetToken, state.StatelessResetTokensByConnectionId[9]);
        Assert.Single(state.StatelessResetTokensByConnectionId);
        Assert.Equal(9UL, state.HighestConnectionIdIssuedToPeer);
    }

    private static byte[] CreateStatelessResetToken(byte startValue)
    {
        byte[] token = new byte[QuicStatelessReset.StatelessResetTokenLength];
        for (int i = 0; i < token.Length; i++)
        {
            token[i] = (byte)(startValue + i);
        }

        return token;
    }
}
