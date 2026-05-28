// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-1373">QUIC frames MUST NOT use a self-describing encoding.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-1373")]
public sealed class REQ_QUIC_RFC9000_1373
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-1373">QUIC frames MUST NOT use a self-describing encoding.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-1373")]
    public void TryFormatTypeOnlyFrames_UseSingleByteFrameTypeEncodings()
    {
        AssertSingleByteEncoding(QuicFrameTestData.BuildPaddingFrame(), 0x00);
        AssertSingleByteEncoding(QuicFrameTestData.BuildPingFrame(), 0x01);
        AssertSingleByteEncoding(QuicFrameTestData.BuildHandshakeDoneFrame(), 0x1E);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-1373">QUIC frames MUST NOT use a self-describing encoding.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-1373")]
    public void TryParseTypeOnlyFrames_RejectsSelfDescribingEnvelopeForms()
    {
        Assert.False(QuicFrameCodec.TryParsePaddingFrame([0x40, 0x00], out _));
        Assert.False(QuicFrameCodec.TryParsePingFrame([0x40, 0x01], out _));
        Assert.False(QuicFrameCodec.TryParseHandshakeDoneFrame([0x40, 0x1E], out _, out _));
    }

    private static void AssertSingleByteEncoding(byte[] encodedFrame, ulong expectedFrameType)
    {
        Assert.True(QuicVariableLengthInteger.TryParse(encodedFrame, out ulong frameType, out int bytesConsumed));
        Assert.Equal(expectedFrameType, frameType);
        Assert.Equal(1, bytesConsumed);
        Assert.Single(encodedFrame);
    }
}
