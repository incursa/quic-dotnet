// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P9-0005">A variable-length integer indicating the maximum amount of data that MAY be sent on the entire connection, in units of bytes.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S19P9-0005")]
public sealed class REQ_QUIC_RFC9000_S19P9_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseMaxDataFrame_RejectsTruncatedConnectionByteLimit()
    {
        byte[] truncatedConnectionByteLimit = [0x10, 0x40];

        Assert.False(QuicFrameCodec.TryParseMaxDataFrame(truncatedConnectionByteLimit, out _, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseMaxDataFrame_AcceptsZeroAndMaximumConnectionByteLimits()
    {
        AssertRoundTripsConnectionByteLimit(0);
        AssertRoundTripsConnectionByteLimit(QuicVariableLengthInteger.MaxValue);
    }

    private static void AssertRoundTripsConnectionByteLimit(ulong maximumData)
    {
        QuicMaxDataFrame frame = new(maximumData);
        byte[] encoded = QuicFrameTestData.BuildMaxDataFrame(frame);

        Assert.True(QuicFrameCodec.TryParseMaxDataFrame(encoded, out QuicMaxDataFrame parsed, out int bytesConsumed));
        Assert.Equal(encoded.Length, bytesConsumed);
        Assert.Equal(maximumData, parsed.MaximumData);

        Span<byte> buffer = stackalloc byte[16];
        Assert.True(QuicFrameCodec.TryFormatMaxDataFrame(parsed, buffer, out int bytesWritten));
        Assert.True(encoded.AsSpan().SequenceEqual(buffer[..bytesWritten]));
    }
}
