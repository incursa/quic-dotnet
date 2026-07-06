// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S19P8_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_StreamFrame_OffsetBitIndicatesOffsetFieldPresence()
    {
        foreach (StreamFrameCase testCase in StreamFrameCases().Where(static testCase => testCase.HasOffset))
        {
            QuicStreamFrame frame = AssertStreamFrameRoundTrip(testCase);

            Assert.True(frame.HasOffset);
            Assert.True((frame.FrameType & QuicStreamFrameBits.OffsetBitMask) != 0);
            Assert.Equal(testCase.Offset, frame.Offset);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0002")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_StreamFrame_WhenOffsetBitIsClearOffsetIsZero()
    {
        foreach (StreamFrameCase testCase in StreamFrameCases().Where(static testCase => !testCase.HasOffset))
        {
            QuicStreamFrame frame = AssertStreamFrameRoundTrip(testCase);

            Assert.False(frame.HasOffset);
            Assert.Equal(0UL, frame.Offset);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0003")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_StreamFrame_LengthBitIndicatesLengthFieldPresence()
    {
        foreach (StreamFrameCase testCase in StreamFrameCases().Where(static testCase => testCase.HasLength))
        {
            QuicStreamFrame frame = AssertStreamFrameRoundTrip(testCase);

            Assert.True(frame.HasLength);
            Assert.Equal((ulong)testCase.StreamDataLength, frame.Length);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0004")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_StreamFrame_WithoutLengthConsumesPacketRemainder()
    {
        foreach (StreamFrameCase testCase in StreamFrameCases().Where(static testCase => !testCase.HasLength))
        {
            byte[] packet = BuildStreamFrame(testCase);
            QuicStreamFrame frame = AssertStreamFrameRoundTrip(testCase);

            Assert.False(frame.HasLength);
            Assert.Equal(0UL, frame.Length);
            Assert.Equal(packet.Length, frame.ConsumedLength);
            Assert.Equal(testCase.StreamDataLength, frame.StreamDataLength);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0005")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_StreamFrame_LengthFieldCanRepresentZeroLengthData()
    {
        foreach (byte frameType in StreamFrameTypes().Where(static frameType => (frameType & QuicStreamFrameBits.LengthBitMask) != 0))
        {
            StreamFrameCase testCase = new(frameType, StreamId: 4, Offset: HasOffset(frameType) ? 0x20UL : 0UL, StreamDataLength: 0);
            QuicStreamFrame frame = AssertStreamFrameRoundTrip(testCase);

            Assert.True(frame.HasLength);
            Assert.Equal(0UL, frame.Length);
            Assert.Equal(0, frame.StreamDataLength);
            Assert.True(frame.StreamData.IsEmpty);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0006")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_StreamFrame_FinBitMarksEndOfStream()
    {
        foreach (StreamFrameCase testCase in StreamFrameCases().Where(static testCase => testCase.IsFin))
        {
            QuicStreamFrame frame = AssertStreamFrameRoundTrip(testCase);

            Assert.True(frame.IsFin);
            Assert.True((frame.FrameType & QuicStreamFrameBits.FinBitMask) != 0);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0008")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_StreamFrame_AcceptsOnlyRegisteredStreamFrameTypes()
    {
        foreach (byte frameType in StreamFrameTypes())
        {
            StreamFrameCase testCase = new(frameType, StreamId: 4, Offset: HasOffset(frameType) ? 1UL : 0UL, StreamDataLength: 1);
            QuicStreamFrame frame = AssertStreamFrameRoundTrip(testCase);

            Assert.Equal(frameType, frame.FrameType);
        }

        foreach (byte frameType in new byte[] { 0x00, 0x06, 0x07, 0x10 })
        {
            Assert.False(QuicStreamParser.TryParseStreamFrame([frameType, 0x00], out _));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0009")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_StreamFrame_StreamIdIsVariableLengthInteger()
    {
        foreach (ulong streamId in new[] { 0UL, 1UL, 4UL, 0x1234UL, QuicVariableLengthInteger.MaxValue })
        {
            StreamFrameCase testCase = new(FrameType: 0x0A, streamId, Offset: 0, StreamDataLength: streamId == QuicVariableLengthInteger.MaxValue ? 0 : 4);
            QuicStreamFrame frame = AssertStreamFrameRoundTrip(testCase);

            Assert.Equal(streamId, frame.StreamId.Value);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0010")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_StreamFrame_OffsetIsVariableLengthIntegerWhenPresent()
    {
        foreach (ulong offset in new[] { 0UL, 1UL, 0x1234UL, QuicVariableLengthInteger.MaxValue })
        {
            StreamFrameCase testCase = new(FrameType: 0x0E, StreamId: 4, offset, StreamDataLength: offset == QuicVariableLengthInteger.MaxValue ? 0 : 4);
            QuicStreamFrame frame = AssertStreamFrameRoundTrip(testCase);

            Assert.True(frame.HasOffset);
            Assert.Equal(offset, frame.Offset);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0011")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_StreamFrame_LengthIsVariableLengthIntegerWhenPresent()
    {
        foreach (int streamDataLength in new[] { 0, 1, 16, 63, 64 })
        {
            StreamFrameCase testCase = new(FrameType: 0x0A, StreamId: 4, Offset: 0, streamDataLength);
            QuicStreamFrame frame = AssertStreamFrameRoundTrip(testCase);

            Assert.True(frame.HasLength);
            Assert.Equal((ulong)streamDataLength, frame.Length);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0013")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_StreamFrame_ReportsNamedStreamIdAndType()
    {
        foreach (ulong streamId in new[] { 0UL, 1UL, 2UL, 3UL, 0x1234UL })
        {
            StreamFrameCase testCase = new(FrameType: 0x0A, streamId, Offset: 0, StreamDataLength: 1);
            QuicStreamFrame frame = AssertStreamFrameRoundTrip(testCase);

            Assert.Equal(streamId, frame.StreamId.Value);
            QuicStreamType expectedStreamType = (streamId & 0x02) == 0
                ? QuicStreamType.Bidirectional
                : QuicStreamType.Unidirectional;
            Assert.Equal(expectedStreamType, frame.StreamType);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0014")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_StreamFrame_ReportsByteOffsetForFrameData()
    {
        foreach (StreamFrameCase testCase in StreamFrameCases().Where(static testCase => testCase.HasOffset))
        {
            QuicStreamFrame frame = AssertStreamFrameRoundTrip(testCase);

            Assert.Equal(testCase.Offset, frame.Offset);
            Assert.Equal(testCase.StreamDataLength, frame.StreamDataLength);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0015")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_StreamFrame_OffsetFieldIsPresentWhenOffBitIsSet()
    {
        foreach (byte frameType in StreamFrameTypes().Where(HasOffset))
        {
            StreamFrameCase testCase = new(frameType, StreamId: 4, Offset: 0x21, StreamDataLength: 1);
            QuicStreamFrame frame = AssertStreamFrameRoundTrip(testCase);

            Assert.True(frame.HasOffset);
            Assert.Equal(0x21UL, frame.Offset);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0016")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_StreamFrame_LengthFieldLimitsStreamData()
    {
        foreach (ulong declaredLength in new[] { 0UL, 1UL, 2UL })
        {
            byte[] packet = QuicS19P8StreamFrameTestSupport.BuildStreamFrameWithDeclaredLength(
                frameType: 0x0A,
                streamId: 4,
                declaredLength,
                streamData: [0xAA, 0xBB, 0xCC]);

            Assert.True(QuicStreamParser.TryParseStreamFrame(packet, out QuicStreamFrame frame));
            Assert.Equal(declaredLength, frame.Length);
            Assert.Equal((int)declaredLength, frame.StreamDataLength);
            Assert.Equal(packet.Length - (3 - (int)declaredLength), frame.ConsumedLength);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0017")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_StreamFrame_LengthFieldIsPresentWhenLenBitIsSet()
    {
        foreach (byte frameType in StreamFrameTypes().Where(HasLength))
        {
            StreamFrameCase testCase = new(frameType, StreamId: 4, Offset: HasOffset(frameType) ? 1UL : 0UL, StreamDataLength: 1);
            QuicStreamFrame frame = AssertStreamFrameRoundTrip(testCase);

            Assert.True(frame.HasLength);
            Assert.Equal(1UL, frame.Length);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0019")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_StreamFrame_OffsetPlusDataCanReachStreamCeiling()
    {
        foreach (byte frameType in new byte[] { 0x0C, 0x0E, 0x0F })
        {
            StreamFrameCase testCase = new(
                frameType,
                StreamId: 0,
                Offset: QuicVariableLengthInteger.MaxValue - 1,
                StreamDataLength: 1);
            QuicStreamFrame frame = AssertStreamFrameRoundTrip(testCase);

            ulong effectiveLength = frame.HasLength ? frame.Length : (ulong)frame.StreamDataLength;
            Assert.Equal(QuicVariableLengthInteger.MaxValue, frame.Offset + effectiveLength);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0020")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_StreamFrame_OffsetPlusDataBeyondCreditIsFlowControlError()
    {
        foreach ((ulong receiveLimit, int streamDataLength) in new[] { (1UL, 2), (4UL, 8), (16UL, 32) })
        {
            QuicConnectionStreamState state =
                QuicConnectionStreamStateTestHelpers.CreateState(connectionReceiveLimit: receiveLimit);
            StreamFrameCase testCase = new(FrameType: 0x0A, StreamId: 1, Offset: 0, streamDataLength);
            QuicStreamFrame frame = AssertStreamFrameRoundTrip(testCase);

            Assert.False(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
            Assert.Equal(QuicTransportErrorCode.FlowControlError, errorCode);
        }
    }

    private static IEnumerable<StreamFrameCase> StreamFrameCases()
    {
        foreach (byte frameType in StreamFrameTypes())
        {
            yield return new StreamFrameCase(
                frameType,
                StreamId: 0,
                Offset: HasOffset(frameType) ? 0UL : 0UL,
                StreamDataLength: 0);
            yield return new StreamFrameCase(
                frameType,
                StreamId: 4,
                Offset: HasOffset(frameType) ? 1UL : 0UL,
                StreamDataLength: 1);
            yield return new StreamFrameCase(
                frameType,
                StreamId: 0x1234,
                Offset: HasOffset(frameType) ? 0x40UL : 0UL,
                StreamDataLength: 16);
        }
    }

    private static IEnumerable<byte> StreamFrameTypes()
    {
        for (byte frameType = QuicStreamFrameBits.StreamFrameTypeMinimum;
            frameType <= QuicStreamFrameBits.StreamFrameTypeMaximum;
            frameType++)
        {
            yield return frameType;
        }
    }

    private static byte[] BuildStreamFrame(StreamFrameCase testCase)
    {
        return QuicStreamTestData.BuildStreamFrame(
            testCase.FrameType,
            testCase.StreamId,
            SequentialBytes(0xA0, testCase.StreamDataLength),
            testCase.Offset);
    }

    private static QuicStreamFrame AssertStreamFrameRoundTrip(StreamFrameCase testCase)
    {
        byte[] packet = BuildStreamFrame(testCase);

        Assert.True(QuicStreamParser.TryParseStreamFrame(packet, out QuicStreamFrame frame));
        Assert.Equal(packet.Length, frame.ConsumedLength);
        Assert.Equal(testCase.FrameType, frame.FrameType);
        Assert.Equal(testCase.StreamId, frame.StreamId.Value);
        Assert.True(SequentialBytes(0xA0, testCase.StreamDataLength).AsSpan().SequenceEqual(frame.StreamData));

        Span<byte> destination = stackalloc byte[512];
        Assert.True(QuicFrameCodec.TryFormatStreamFrame(
            frame.FrameType,
            frame.StreamId.Value,
            frame.Offset,
            frame.StreamData,
            destination,
            out int bytesWritten));
        Assert.Equal(packet.Length, bytesWritten);
        Assert.True(packet.AsSpan().SequenceEqual(destination[..bytesWritten]));
        return frame;
    }

    private static bool HasOffset(byte frameType) => (frameType & QuicStreamFrameBits.OffsetBitMask) != 0;

    private static bool HasLength(byte frameType) => (frameType & QuicStreamFrameBits.LengthBitMask) != 0;

    private static byte[] SequentialBytes(byte seed, int length)
    {
        byte[] bytes = new byte[length];
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = unchecked((byte)(seed + i));
        }

        return bytes;
    }

    private readonly record struct StreamFrameCase(
        byte FrameType,
        ulong StreamId,
        ulong Offset,
        int StreamDataLength)
    {
        public bool HasOffset => (FrameType & QuicStreamFrameBits.OffsetBitMask) != 0;

        public bool HasLength => (FrameType & QuicStreamFrameBits.LengthBitMask) != 0;

        public bool IsFin => (FrameType & QuicStreamFrameBits.FinBitMask) != 0;
    }
}
