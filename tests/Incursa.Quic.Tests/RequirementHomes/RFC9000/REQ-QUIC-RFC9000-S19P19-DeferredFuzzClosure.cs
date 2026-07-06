// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S19P19_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P19-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ConnectionCloseFrame_TransportTypeSignalsOnlyQuicLayerErrors()
    {
        foreach ((ulong errorCode, byte[] reasonPhrase) in CloseReasonCases())
        {
            byte[] encoded = QuicConnectionCloseFrameProofSupport.BuildTransportClose(
                errorCode,
                triggeringFrameType: 0x02,
                reasonPhrase);

            QuicConnectionCloseFrame parsed = AssertConnectionCloseRoundTrip(encoded);

            Assert.False(parsed.IsApplicationError);
            Assert.Equal((byte)0x1C, parsed.FrameType);
            Assert.Equal(errorCode, parsed.ErrorCode);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P19-0002")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ConnectionCloseFrame_ApplicationTypeSignalsApplicationErrors()
    {
        foreach ((ulong errorCode, byte[] reasonPhrase) in CloseReasonCases())
        {
            byte[] encoded = QuicConnectionCloseFrameProofSupport.BuildApplicationClose(errorCode, reasonPhrase);

            QuicConnectionCloseFrame parsed = AssertConnectionCloseRoundTrip(encoded);

            Assert.True(parsed.IsApplicationError);
            Assert.Equal((byte)0x1D, parsed.FrameType);
            Assert.Equal(errorCode, parsed.ErrorCode);
            Assert.False(parsed.HasTriggeringFrameType);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P19-0003")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ConnectionCloseFrame_TypeFieldAcceptsOnlyConnectionCloseValues()
    {
        foreach (byte frameType in new byte[] { 0x1C, 0x1D })
        {
            byte[] encoded = frameType == 0x1C
                ? QuicConnectionCloseFrameProofSupport.BuildTransportClose(reasonPhrase: [])
                : QuicConnectionCloseFrameProofSupport.BuildApplicationClose(reasonPhrase: []);

            QuicConnectionCloseFrame parsed = AssertConnectionCloseRoundTrip(encoded);

            Assert.Equal(frameType, parsed.FrameType);
        }

        foreach (byte frameType in new byte[] { 0x1B, 0x1E, 0x20, 0x3F })
        {
            Assert.False(QuicFrameCodec.TryParseConnectionCloseFrame([frameType, 0x00], out _, out _));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P19-0004")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ConnectionCloseFrame_ErrorCodeIsVariableLengthInteger()
    {
        foreach (ulong errorCode in VarintCases())
        {
            byte[] encoded = QuicConnectionCloseFrameProofSupport.BuildTransportClose(
                errorCode,
                triggeringFrameType: 0,
                reasonPhrase: []);

            QuicConnectionCloseFrame parsed = AssertConnectionCloseRoundTrip(encoded);

            Assert.Equal(errorCode, parsed.ErrorCode);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P19-0005")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ConnectionCloseFrame_TriggeringFrameTypeIsVariableLengthIntegerWhenPresent()
    {
        foreach (ulong triggeringFrameType in VarintCases())
        {
            byte[] encoded = QuicConnectionCloseFrameProofSupport.BuildTransportClose(
                errorCode: 0x1234,
                triggeringFrameType,
                reasonPhrase: []);

            QuicConnectionCloseFrame parsed = AssertConnectionCloseRoundTrip(encoded);

            Assert.True(parsed.HasTriggeringFrameType);
            Assert.Equal(triggeringFrameType, parsed.TriggeringFrameType);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P19-0006")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ConnectionCloseFrame_ReasonPhraseLengthIsVariableLengthInteger()
    {
        foreach (int length in new[] { 0, 1, 2, 63, 64, 128 })
        {
            byte[] reasonPhrase = SequentialBytes(0x30, length);
            byte[] encoded = QuicConnectionCloseFrameProofSupport.BuildApplicationClose(0x1234, reasonPhrase);

            QuicConnectionCloseFrame parsed = AssertConnectionCloseRoundTrip(encoded);

            Assert.Equal(length, parsed.ReasonPhrase.Length);
            Assert.True(reasonPhrase.AsSpan().SequenceEqual(parsed.ReasonPhrase));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P19-0008")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ConnectionCloseFrame_ErrorCodeIndicatesTheCloseReason()
    {
        foreach (ulong errorCode in new[] { 0UL, 1UL, 10UL, 0x100UL, QuicVariableLengthInteger.MaxValue })
        {
            QuicConnectionCloseFrame transportFrame = AssertConnectionCloseRoundTrip(
                QuicConnectionCloseFrameProofSupport.BuildTransportClose(errorCode, 0x02, []));
            QuicConnectionCloseFrame applicationFrame = AssertConnectionCloseRoundTrip(
                QuicConnectionCloseFrameProofSupport.BuildApplicationClose(errorCode, []));

            Assert.Equal(errorCode, transportFrame.ErrorCode);
            Assert.Equal(errorCode, applicationFrame.ErrorCode);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P19-0010")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ConnectionCloseFrame_ApplicationVariantPreservesApplicationErrorCodeSpace()
    {
        foreach (ulong applicationErrorCode in VarintCases())
        {
            QuicConnectionCloseFrame parsed = AssertConnectionCloseRoundTrip(
                QuicConnectionCloseFrameProofSupport.BuildApplicationClose(applicationErrorCode, []));

            Assert.True(parsed.IsApplicationError);
            Assert.Equal(applicationErrorCode, parsed.ErrorCode);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P19-0011")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ConnectionCloseFrame_FrameTypeFieldIdentifiesTheTriggeringFrame()
    {
        foreach (ulong triggeringFrameType in new[] { 0UL, 1UL, 0x06UL, 0x18UL, 0x1CUL, QuicVariableLengthInteger.MaxValue })
        {
            QuicConnectionCloseFrame parsed = AssertConnectionCloseRoundTrip(
                QuicConnectionCloseFrameProofSupport.BuildTransportClose(0x1234, triggeringFrameType, []));

            Assert.True(parsed.HasTriggeringFrameType);
            Assert.Equal(triggeringFrameType, parsed.TriggeringFrameType);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P19-0012")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ConnectionCloseFrame_UnknownTriggeringFrameTypeUsesPaddingValueZero()
    {
        foreach (ulong errorCode in new[] { 0UL, 0x1234UL, QuicVariableLengthInteger.MaxValue })
        {
            QuicConnectionCloseFrame frame = new(errorCode, triggeringFrameType: 0, reasonPhrase: []);
            byte[] destination = new byte[32];

            Assert.True(QuicFrameCodec.TryFormatConnectionCloseFrame(frame, destination, out int bytesWritten));
            Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(
                destination[..bytesWritten],
                out QuicConnectionCloseFrame parsed,
                out int bytesConsumed));
            Assert.Equal(bytesWritten, bytesConsumed);
            Assert.Equal(0UL, parsed.TriggeringFrameType);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P19-0014")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ConnectionCloseFrame_ReasonPhraseLengthBoundsReasonBytes()
    {
        foreach (int length in new[] { 0, 1, 3, 63, 64 })
        {
            byte[] reasonPhrase = SequentialBytes(0x40, length);
            byte[] encoded = QuicConnectionCloseFrameProofSupport.BuildTransportClose(
                errorCode: 0x1234,
                triggeringFrameType: 0x02,
                reasonPhrase);

            QuicConnectionCloseFrame parsed = AssertConnectionCloseRoundTrip(encoded);

            Assert.Equal(length, parsed.ReasonPhrase.Length);
            Assert.True(reasonPhrase.AsSpan().SequenceEqual(parsed.ReasonPhrase));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P19-0015")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ConnectionCloseFrame_ReasonPhraseMustFitWithinSinglePacketBuffer()
    {
        foreach (int length in new[] { 0, 1, 16, 64 })
        {
            QuicConnectionCloseFrame frame = new(0x1234, 0x02, SequentialBytes(0x50, length));
            byte[] encoded = QuicFrameTestData.BuildConnectionCloseFrame(frame);
            byte[] destination = new byte[encoded.Length];

            Assert.True(QuicFrameCodec.TryFormatConnectionCloseFrame(frame, destination, out int bytesWritten));
            Assert.Equal(encoded.Length, bytesWritten);

            if (encoded.Length > 0)
            {
                Assert.False(QuicFrameCodec.TryFormatConnectionCloseFrame(frame, new byte[encoded.Length - 1], out _));
            }
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P19-0016")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ConnectionCloseFrame_AllowsZeroLengthReasonPhrase()
    {
        foreach (bool isApplicationError in new[] { false, true })
        {
            byte[] encoded = isApplicationError
                ? QuicConnectionCloseFrameProofSupport.BuildApplicationClose(reasonPhrase: [])
                : QuicConnectionCloseFrameProofSupport.BuildTransportClose(reasonPhrase: []);

            QuicConnectionCloseFrame parsed = AssertConnectionCloseRoundTrip(encoded);

            Assert.Empty(parsed.ReasonPhrase.ToArray());
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P19-0017")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ConnectionCloseFrame_PreservesUtf8ReasonPhraseBytes()
    {
        foreach (byte[] reasonPhrase in new[]
        {
            [],
            new byte[] { 0x6F, 0x6B },
            new byte[] { 0xE2, 0x9C, 0x93 },
            new byte[] { 0xF0, 0x9F, 0x94, 0x92 },
        })
        {
            QuicConnectionCloseFrame parsed = AssertConnectionCloseRoundTrip(
                QuicConnectionCloseFrameProofSupport.BuildApplicationClose(0x1234, reasonPhrase));

            Assert.True(reasonPhrase.AsSpan().SequenceEqual(parsed.ReasonPhrase));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P19-0018")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ConnectionCloseFrame_ApplicationVariantStaysInApplicationPacketSpace()
    {
        foreach ((ulong errorCode, byte[] reasonPhrase) in CloseReasonCases())
        {
            byte[] payload = QuicConnectionCloseFrameProofSupport.BuildApplicationClose(errorCode, reasonPhrase);
            byte[] applicationPacket = QuicHeaderTestData.BuildShortHeader(0x00, payload);

            Assert.True(QuicPacketParser.TryGetPacketNumberSpace(applicationPacket, out QuicPacketNumberSpace packetNumberSpace));
            Assert.Equal(QuicPacketNumberSpace.ApplicationData, packetNumberSpace);

            QuicConnectionCloseFrame parsed = AssertConnectionCloseRoundTrip(payload);
            Assert.True(parsed.IsApplicationError);
        }
    }

    private static QuicConnectionCloseFrame AssertConnectionCloseRoundTrip(byte[] encoded)
    {
        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(encoded, out QuicConnectionCloseFrame parsed, out int bytesConsumed));
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[512];
        Assert.True(QuicFrameCodec.TryFormatConnectionCloseFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
        return parsed;
    }

    private static IEnumerable<(ulong ErrorCode, byte[] ReasonPhrase)> CloseReasonCases()
    {
        yield return (0, []);
        yield return (1, [0x6F, 0x6B]);
        yield return (0x1234, SequentialBytes(0x20, 16));
        yield return (QuicVariableLengthInteger.MaxValue, SequentialBytes(0x40, 63));
    }

    private static ulong[] VarintCases()
    {
        return [0, 1, 63, 64, 16_383, 16_384, QuicVariableLengthInteger.MaxValue];
    }

    private static byte[] SequentialBytes(byte seed, int length)
    {
        byte[] bytes = new byte[length];
        for (int index = 0; index < bytes.Length; index++)
        {
            bytes[index] = unchecked((byte)(seed + index));
        }

        return bytes;
    }
}
