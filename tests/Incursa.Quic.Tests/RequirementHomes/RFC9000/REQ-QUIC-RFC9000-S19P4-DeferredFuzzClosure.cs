// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S19P4_DeferredFuzzClosure
{
    private const byte ResetStreamFrameType = 0x04;

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0004")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ResetStreamFrame_TypeFieldIsFixedValue04()
    {
        foreach (QuicResetStreamFrame frame in FrameCases())
        {
            byte[] encoded = QuicFrameTestData.BuildResetStreamFrame(frame);

            Assert.Equal(ResetStreamFrameType, encoded[0]);
            AssertResetStreamRoundTrip(frame);
        }

        foreach (byte frameType in new byte[] { 0x03, 0x05, 0x08 })
        {
            Assert.False(QuicFrameCodec.TryParseResetStreamFrame([frameType, 0x00, 0x00, 0x00], out _, out _));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0005")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ResetStreamFrame_StreamIdIsVariableLengthInteger()
    {
        foreach (ulong streamId in VarintCases())
        {
            QuicResetStreamFrame parsed = AssertResetStreamRoundTrip(new QuicResetStreamFrame(
                streamId,
                applicationProtocolErrorCode: 0,
                finalSize: 0));

            Assert.Equal(streamId, parsed.StreamId);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0006")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ResetStreamFrame_ApplicationProtocolErrorCodeIsVariableLengthInteger()
    {
        foreach (ulong errorCode in VarintCases())
        {
            QuicResetStreamFrame parsed = AssertResetStreamRoundTrip(new QuicResetStreamFrame(
                streamId: 1,
                errorCode,
                finalSize: 0));

            Assert.Equal(errorCode, parsed.ApplicationProtocolErrorCode);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0007")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ResetStreamFrame_FinalSizeIsVariableLengthInteger()
    {
        foreach (ulong finalSize in VarintCases())
        {
            QuicResetStreamFrame parsed = AssertResetStreamRoundTrip(new QuicResetStreamFrame(
                streamId: 1,
                applicationProtocolErrorCode: 0,
                finalSize));

            Assert.Equal(finalSize, parsed.FinalSize);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0009")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ResetStreamFrame_StreamIdIdentifiesTerminatedStream()
    {
        foreach (QuicResetStreamFrame frame in FrameCases())
        {
            QuicResetStreamFrame parsed = AssertResetStreamRoundTrip(frame);

            Assert.Equal(frame.StreamId, parsed.StreamId);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0010")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ResetStreamFrame_ApplicationErrorCodeIndicatesCloseReason()
    {
        foreach (QuicResetStreamFrame frame in FrameCases())
        {
            QuicResetStreamFrame parsed = AssertResetStreamRoundTrip(frame);

            Assert.Equal(frame.ApplicationProtocolErrorCode, parsed.ApplicationProtocolErrorCode);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0011")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ResetStreamFrame_FinalSizeIndicatesStreamFinalSizeInBytes()
    {
        foreach (QuicResetStreamFrame frame in FrameCases())
        {
            QuicResetStreamFrame parsed = AssertResetStreamRoundTrip(frame);

            Assert.Equal(frame.FinalSize, parsed.FinalSize);
        }
    }

    private static QuicResetStreamFrame AssertResetStreamRoundTrip(QuicResetStreamFrame frame)
    {
        byte[] encoded = QuicFrameTestData.BuildResetStreamFrame(frame);
        Assert.True(QuicFrameCodec.TryParseResetStreamFrame(encoded, out QuicResetStreamFrame parsed, out int bytesConsumed));
        Assert.Equal(encoded.Length, bytesConsumed);
        Assert.Equal(frame.StreamId, parsed.StreamId);
        Assert.Equal(frame.ApplicationProtocolErrorCode, parsed.ApplicationProtocolErrorCode);
        Assert.Equal(frame.FinalSize, parsed.FinalSize);

        byte[] destination = new byte[encoded.Length];
        Assert.True(QuicFrameCodec.TryFormatResetStreamFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination));

        if (encoded.Length > 1)
        {
            Assert.False(QuicFrameCodec.TryParseResetStreamFrame(encoded[..^1], out _, out _));
        }

        return parsed;
    }

    private static IEnumerable<QuicResetStreamFrame> FrameCases()
    {
        yield return new QuicResetStreamFrame(streamId: 0, applicationProtocolErrorCode: 0, finalSize: 0);
        yield return new QuicResetStreamFrame(streamId: 1, applicationProtocolErrorCode: 1, finalSize: 1);
        yield return new QuicResetStreamFrame(streamId: 63, applicationProtocolErrorCode: 64, finalSize: 16_383);
        yield return new QuicResetStreamFrame(streamId: 64, applicationProtocolErrorCode: 16_383, finalSize: 16_384);
        yield return new QuicResetStreamFrame(streamId: QuicVariableLengthInteger.MaxValue, applicationProtocolErrorCode: 0x1234, finalSize: 0);
        yield return new QuicResetStreamFrame(streamId: 4, applicationProtocolErrorCode: QuicVariableLengthInteger.MaxValue, finalSize: QuicVariableLengthInteger.MaxValue);
    }

    private static ulong[] VarintCases()
    {
        return [0, 1, 63, 64, 16_383, 16_384, QuicVariableLengthInteger.MaxValue];
    }
}
