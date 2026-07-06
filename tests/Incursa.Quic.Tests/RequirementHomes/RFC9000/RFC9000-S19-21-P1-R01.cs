// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S19-21-P1-R01">An endpoint MUST understand the syntax of all frames before it can successfully process a packet.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S19-21-P1-R01")]
public sealed class RFC9000_S19_21_P1_R01
{
    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="RFC9000-S19-21-P1-R01">An endpoint MUST understand the syntax of all frames before it can successfully process a packet.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("RFC9000-S19-21-P1-R01")]
    public void TryParseTypeOnlyFrames_ConsumesOnlyTheDeclaredFrameSyntax()
    {
        byte[] packet =
        [
            0x00,
            0x01,
            0x1E,
            0xAA,
        ];

        Assert.True(QuicFrameCodec.TryParsePaddingFrame(packet, out int paddingConsumed));
        Assert.Equal(1, paddingConsumed);

        Assert.True(QuicFrameCodec.TryParsePingFrame(packet[paddingConsumed..], out int pingConsumed));
        Assert.Equal(1, pingConsumed);

        Assert.True(QuicFrameCodec.TryParseHandshakeDoneFrame(packet[(paddingConsumed + pingConsumed)..], out _, out int handshakeConsumed));
        Assert.Equal(1, handshakeConsumed);

        Assert.Equal(3, paddingConsumed + pingConsumed + handshakeConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="RFC9000-S19-21-P1-R01">An endpoint MUST understand the syntax of all frames before it can successfully process a packet.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("RFC9000-S19-21-P1-R01")]
    public void TryParseTypeOnlyFrames_RejectsEmptyAndMismatchedTypes()
    {
        Assert.False(QuicFrameCodec.TryParsePaddingFrame([], out _));
        Assert.False(QuicFrameCodec.TryParsePingFrame([0x00], out _));
        Assert.False(QuicFrameCodec.TryParseHandshakeDoneFrame([0x40, 0x1E], out _, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    [Requirement("RFC9000-S19-21-P1-R01")]
    public void TryParseTypeOnlyFramesFuzz_ConsumesKnownSyntaxWithoutOverreadingTrailingBytes()
    {
        (byte[] Packet, int KnownSyntaxLength)[] cases =
        [
            ([0x00, 0x01, 0x1E, 0xAA], 3),
            ([0x01, 0x1E, 0xAA], 2),
            ([0x00, 0x00, 0x01, 0x1E, 0xAA], 4),
            ([0x1E, 0x00, 0x01, 0xAA], 3),
        ];

        foreach ((byte[] packet, int knownSyntaxLength) in cases)
        {
            int offset = 0;
            while (offset < knownSyntaxLength)
            {
                Assert.True(TryParseKnownTypeOnlyFrame(packet.AsSpan(offset), out int bytesConsumed));
                Assert.True(bytesConsumed > 0);
                offset += bytesConsumed;
            }

            Assert.Equal(knownSyntaxLength, offset);
            Assert.Equal(0xAA, packet[offset]);
        }
    }

    private static bool TryParseKnownTypeOnlyFrame(ReadOnlySpan<byte> packet, out int bytesConsumed)
    {
        bytesConsumed = 0;
        return packet[0] switch
        {
            0x00 => QuicFrameCodec.TryParsePaddingFrame(packet, out bytesConsumed),
            0x01 => QuicFrameCodec.TryParsePingFrame(packet, out bytesConsumed),
            0x1E => QuicFrameCodec.TryParseHandshakeDoneFrame(packet, out _, out bytesConsumed),
            _ => false,
        };
    }
}
