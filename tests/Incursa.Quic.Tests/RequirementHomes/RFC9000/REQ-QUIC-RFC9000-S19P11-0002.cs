// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P11-0002")]
public sealed class REQ_QUIC_RFC9000_S19P11_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseMaxStreamsFrame_PreservesTheMaximumStreamsVarintValue()
    {
        QuicMaxStreamsFrame frame = new(isBidirectional: true, maximumStreams: 0x1234);
        byte[] encoded = QuicFrameTestData.BuildMaxStreamsFrame(frame);

        Assert.True(QuicFrameCodec.TryParseMaxStreamsFrame(encoded, out QuicMaxStreamsFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.MaximumStreams, parsed.MaximumStreams);
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[16];
        Assert.True(QuicFrameCodec.TryFormatMaxStreamsFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseMaxStreamsFrame_RejectsATruncatedMaximumStreamsVarint()
    {
        byte[] encodedWithTruncatedTwoByteMaximumStreams = [0x12, 0x40];

        Assert.False(QuicFrameCodec.TryParseMaxStreamsFrame(encodedWithTruncatedTwoByteMaximumStreams, out _, out _));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseMaxStreamsFrame_AcceptsTheLargestPermittedMaximumStreamsVarint(bool isBidirectional)
    {
        ulong maximumPermittedStreams = 1UL << 60;
        QuicMaxStreamsFrame frame = new(isBidirectional, maximumPermittedStreams);
        byte[] encoded = QuicFrameTestData.BuildMaxStreamsFrame(frame);

        Assert.True(QuicFrameCodec.TryParseMaxStreamsFrame(encoded, out QuicMaxStreamsFrame parsed, out int bytesConsumed));
        Assert.Equal(frame, parsed);
        Assert.Equal(encoded.Length, bytesConsumed);
    }
}
