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
}
