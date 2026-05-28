// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P4-0006")]
public sealed class REQ_QUIC_RFC9000_S19P4_0006
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0006")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseResetStreamFrame_DecodesVariableLengthApplicationErrorField()
    {
        byte[] encoded = QuicStreamControlFrameTestSupport.BuildResetStreamPayload(
            QuicVarintTestData.EncodeMinimal(0x04),
            QuicVarintTestData.EncodeMinimal(0x40),
            QuicVarintTestData.EncodeWithLength(0x1234, 2),
            QuicVarintTestData.EncodeMinimal(0x66));

        Assert.True(QuicFrameCodec.TryParseResetStreamFrame(encoded, out QuicResetStreamFrame parsed, out int bytesConsumed));
        Assert.Equal(encoded.Length, bytesConsumed);
        Assert.Equal(0x1234UL, parsed.ApplicationProtocolErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0006")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseResetStreamFrame_RejectsTruncatedApplicationErrorField()
    {
        byte[] applicationErrorCode = QuicVarintTestData.EncodeWithLength(0x1234, 2);
        byte[] encoded = QuicStreamControlFrameTestSupport.BuildResetStreamPayload(
            QuicVarintTestData.EncodeMinimal(0x04),
            QuicVarintTestData.EncodeMinimal(0x40),
            applicationErrorCode[..1],
            QuicVarintTestData.EncodeMinimal(0x66));

        Assert.False(QuicFrameCodec.TryParseResetStreamFrame(encoded, out _, out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0006")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseResetStreamFrame_RoundTripsMaximumApplicationErrorField()
    {
        QuicResetStreamFrame frame = new(
            streamId: 0x40,
            applicationProtocolErrorCode: QuicVariableLengthInteger.MaxValue,
            finalSize: 0x66);
        byte[] encoded = QuicFrameTestData.BuildResetStreamFrame(frame);

        Assert.True(QuicFrameCodec.TryParseResetStreamFrame(encoded, out QuicResetStreamFrame parsed, out int bytesConsumed));
        Assert.Equal(encoded.Length, bytesConsumed);
        Assert.Equal(QuicVariableLengthInteger.MaxValue, parsed.ApplicationProtocolErrorCode);

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicFrameCodec.TryFormatResetStreamFrame(parsed, destination, out int bytesWritten));
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }
}
