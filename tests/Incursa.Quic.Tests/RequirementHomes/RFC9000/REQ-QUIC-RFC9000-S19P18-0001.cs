// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P18-0001")]
public sealed class REQ_QUIC_RFC9000_S19P18_0001
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P18-0001">The Type field MUST be encoded as a variable-length integer with value 0x1b.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P18-0002">The Data field MUST be 64 bits long.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P18-0001")]
    [Requirement("REQ-QUIC-RFC9000-S19P18-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParsePathResponseFrame_ParsesAndFormatsTheEightBytePayload()
    {
        byte[] data = [
            0xA0, 0xA1, 0xA2, 0xA3,
            0xA4, 0xA5, 0xA6, 0xA7];

        QuicPathResponseFrame frame = new(data);
        byte[] encoded = QuicFrameTestData.BuildPathResponseFrame(frame);

        Assert.True(QuicFrameCodec.TryParsePathResponseFrame(encoded, out QuicPathResponseFrame parsed, out int bytesConsumed));
        Assert.True(data.AsSpan().SequenceEqual(parsed.Data));
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[16];
        Assert.True(QuicFrameCodec.TryFormatPathResponseFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParsePathResponseFrame_RejectsANonMinimalTypeEncoding()
    {
        byte[] encoded = [
            0x40, 0x1B,
            0xA0, 0xA1, 0xA2, 0xA3,
            0xA4, 0xA5, 0xA6, 0xA7];

        Assert.False(QuicFrameCodec.TryParsePathResponseFrame(encoded, out _, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryFormatPathResponseFrame_WritesTheFixedTypeAtTheMinimumBoundary()
    {
        QuicPathResponseFrame frame = new([
            0xA0, 0xA1, 0xA2, 0xA3,
            0xA4, 0xA5, 0xA6, 0xA7]);

        Span<byte> destination = stackalloc byte[9];
        Assert.True(QuicFrameCodec.TryFormatPathResponseFrame(frame, destination, out int bytesWritten));
        Assert.Equal(destination.Length, bytesWritten);
        Assert.Equal(0x1B, destination[0]);

        Assert.True(QuicFrameCodec.TryParsePathResponseFrame(destination, out QuicPathResponseFrame parsed, out int bytesConsumed));
        Assert.Equal(bytesWritten, bytesConsumed);
        Assert.True(frame.Data.SequenceEqual(parsed.Data));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void Fuzz_PathResponseFrame_RoundTripsRepresentativeShapesAndRejectsTruncation()
    {
        QuicFrameCodecPart4FuzzSupport.FuzzPathResponseFrame();
    }
}
