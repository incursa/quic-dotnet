// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-1237")]
public sealed class REQ_QUIC_RFC9000_1237
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S20P1-0004")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [Requirement("REQ-QUIC-RFC9000-S20P1-0004")]
    public void TryAddFrame_ReportsCryptoBufferExceededForFramesBeyondTheStreamLimit()
    {
        QuicCryptoBuffer buffer = new();

        Assert.False(buffer.TryAddFrame(
            new QuicCryptoFrame(QuicVariableLengthInteger.MaxValue, [0xAA]),
            out QuicCryptoBufferResult result));
        Assert.Equal(QuicCryptoBufferResult.BufferExceeded, result);
        Assert.Equal(0x0DUL, (ulong)QuicTransportErrorCode.CryptoBufferExceeded);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseCryptoFrame_RejectsFramesThatExceedTheStreamCeiling()
    {
        byte[] encoded = QuicFrameTestData.BuildCryptoFrame(new QuicCryptoFrame(QuicVariableLengthInteger.MaxValue, [0xAA]));

        Assert.False(QuicFrameCodec.TryParseCryptoFrame(encoded, out _, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryFormatCryptoFrame_RejectsFramesThatExceedTheStreamCeiling()
    {
        QuicCryptoFrame frame = new(QuicVariableLengthInteger.MaxValue, [0xAA]);

        Assert.False(QuicFrameCodec.TryFormatCryptoFrame(frame, stackalloc byte[16], out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryAddFrame_AcceptsFramesThatEndExactlyAtTheStreamLimit()
    {
        QuicCryptoBuffer buffer = new();

        Assert.True(buffer.TryAddFrame(
            new QuicCryptoFrame(QuicVariableLengthInteger.MaxValue - 1, [0xAA]),
            out QuicCryptoBufferResult result));
        Assert.Equal(QuicCryptoBufferResult.Buffered, result);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_CryptoFramesAtOrBeyondStreamCeilingAreAcceptedOrRejectedByExactEndOffset()
    {
        byte[] destination = new byte[64];
        foreach (int length in new[] { 1, 2, 8, 16 })
        {
            byte[] cryptoData = Enumerable.Range(0, length).Select(value => (byte)(0xA0 + value)).ToArray();
            ulong acceptedOffset = QuicVariableLengthInteger.MaxValue - (ulong)length;
            QuicCryptoFrame acceptedFrame = new(acceptedOffset, cryptoData);

            Assert.True(QuicFrameCodec.TryFormatCryptoFrame(acceptedFrame, destination, out int bytesWritten));
            Assert.True(QuicFrameCodec.TryParseCryptoFrame(
                destination.AsSpan(0, bytesWritten),
                out QuicCryptoFrame parsed,
                out int bytesConsumed));
            Assert.Equal(bytesWritten, bytesConsumed);
            Assert.Equal(acceptedOffset, parsed.Offset);
            Assert.True(cryptoData.AsSpan().SequenceEqual(parsed.CryptoData));

            QuicCryptoFrame rejectedFrame = new(acceptedOffset + 1, cryptoData);
            Assert.False(QuicFrameCodec.TryFormatCryptoFrame(rejectedFrame, destination, out _));
            byte[] rejectedEncoded = QuicFrameTestData.BuildCryptoFrame(rejectedFrame);
            Assert.False(QuicFrameCodec.TryParseCryptoFrame(rejectedEncoded, out _, out _));
        }
    }
}
