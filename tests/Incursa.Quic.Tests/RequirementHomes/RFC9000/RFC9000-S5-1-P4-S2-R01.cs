// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S5-1-P4-S2-R01">The same connection ID MUST NOT be issued more than once on the same connection.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S5-1-P4-S2-R01")]
public sealed class REQ_QUIC_RFC9000_0209
{
    [Fact]
    [Requirement("RFC9000-S5-1-P4-S2-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryRegisterIssuedConnectionId_RejectsReissuedConnectionIdBytes()
    {
        QuicConnectionIssuedConnectionIdState state = new();
        byte[] connectionIdBytes = [0x10, 0x11, 0x12, 0x13];

        Assert.True(state.TryRegisterIssuedConnectionId(
            connectionId: 1UL,
            connectionIdBytes,
            CreateStatelessResetToken(0x20),
            peerActiveConnectionIdLimit: 4UL));

        Assert.False(state.TryRegisterIssuedConnectionId(
            connectionId: 2UL,
            connectionIdBytes.ToArray(),
            CreateStatelessResetToken(0x30),
            peerActiveConnectionIdLimit: 4UL));
        Assert.Equal(1, state.IssuedConnectionIdCount);
    }

    [Fact]
    [Requirement("RFC9000-S5-1-P4-S2-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryRegisterIssuedConnectionId_AllowsDistinctConnectionIdBytes()
    {
        QuicConnectionIssuedConnectionIdState state = new();

        Assert.True(state.TryRegisterIssuedConnectionId(
            connectionId: 1UL,
            connectionIdBytes: [0x20, 0x21, 0x22, 0x23],
            CreateStatelessResetToken(0x40),
            peerActiveConnectionIdLimit: 4UL));
        Assert.True(state.TryRegisterIssuedConnectionId(
            connectionId: 2UL,
            connectionIdBytes: [0x30, 0x31, 0x32, 0x33],
            CreateStatelessResetToken(0x50),
            peerActiveConnectionIdLimit: 4UL));

        Assert.Equal(2, state.IssuedConnectionIdCount);
        Assert.Equal(2UL, state.HighestConnectionIdIssuedToPeer);
    }

    [Fact]
    [Requirement("RFC9000-S5-1-P4-S2-R01")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryRegisterIssuedConnectionId_RejectsDuplicateIssuedSequenceNumber()
    {
        QuicConnectionIssuedConnectionIdState state = new();

        Assert.True(state.TryRegisterIssuedConnectionId(
            connectionId: 7UL,
            connectionIdBytes: [0x40, 0x41, 0x42, 0x43],
            CreateStatelessResetToken(0x60),
            peerActiveConnectionIdLimit: 4UL));

        Assert.False(state.TryRegisterIssuedConnectionId(
            connectionId: 7UL,
            connectionIdBytes: [0x50, 0x51, 0x52, 0x53],
            CreateStatelessResetToken(0x70),
            peerActiveConnectionIdLimit: 4UL));
        Assert.Equal(1, state.IssuedConnectionIdCount);
    }

    [Fact]
    [Requirement("RFC9000-S5-1-P4-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void TryRegisterIssuedConnectionIdFuzz_RejectsReissuedConnectionIdBytes()
    {
        for (ulong sequenceNumber = 1; sequenceNumber <= 8; sequenceNumber++)
        {
            QuicConnectionIssuedConnectionIdState state = new();
            byte[] connectionIdBytes =
            [
                unchecked((byte)(0x60 + sequenceNumber)),
                unchecked((byte)(0x70 + sequenceNumber)),
                unchecked((byte)(0x80 + sequenceNumber)),
                unchecked((byte)(0x90 + sequenceNumber)),
            ];

            Assert.True(state.TryRegisterIssuedConnectionId(
                sequenceNumber,
                connectionIdBytes,
                CreateStatelessResetToken(unchecked((byte)(0xA0 + sequenceNumber))),
                peerActiveConnectionIdLimit: 4UL));

            Assert.False(state.TryRegisterIssuedConnectionId(
                sequenceNumber + 100UL,
                connectionIdBytes.ToArray(),
                CreateStatelessResetToken(unchecked((byte)(0xB0 + sequenceNumber))),
                peerActiveConnectionIdLimit: 4UL));

            Assert.Equal(1, state.IssuedConnectionIdCount);
            Assert.Equal(sequenceNumber, state.HighestConnectionIdIssuedToPeer);
        }
    }

    private static byte[] CreateStatelessResetToken(byte startValue)
    {
        byte[] token = new byte[QuicStatelessReset.StatelessResetTokenLength];
        for (int index = 0; index < token.Length; index++)
        {
            token[index] = unchecked((byte)(startValue + index));
        }

        return token;
    }
}
